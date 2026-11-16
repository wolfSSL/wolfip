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
make CROSS_COMPILE=aarch64-none-elf- LAYOUT=ddr EL=2 # entered at EL2 by wolfBoot
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

## Firmware update under wolfBoot (QSPI, HTTPS)

`OTA=1` builds the application as a wolfBoot payload that can update itself over the network. wolfBoot (EL2, after PLM, PSM and BL31) keeps two fixed image slots in the QSPI flash, loads the higher version into DDR and passes the slot it chose in the device tree (`/chosen/wolfboot,boot-part`).

```
make LAYOUT=ddr EL=2 OTA=1 OTA_VERSION=2 \
     WOLFBOOT=/path/to/wolfBoot WOLFSSL=/path/to/wolfssl \
     OTA_CERTS=host/certs OTA_SERVER_IP=192.168.2.1 \
     STATIC_IP=192.168.2.2 STATIC_GW=192.168.2.1
```

- `WOLFBOOT` is a wolfBoot tree already built for the matching Versal QSPI configuration (see below); it must provide `wolfBoot_success_part()`, `wolfBoot_update_trigger_part()` and `DUALBOOT_ROLLBACK_UNCONFIRMED`. Its flash driver and slot-state code are compiled into the application and take the partition layout from its generated `include/target.h`.
- `WOLFSSL` is a wolfSSL source tree; the files needed for a TLS 1.3 client are compiled in with `user_settings.h` from this directory.
- `OTA_CERTS` is a directory holding `ota_certs.h` with `ca_cert_der`, `device_cert_der` and `device_key_der`. `host/gen_certs.sh` writes a demonstration set.
- `STATIC_IP` / `STATIC_GW` replace DHCP with a fixed address. Leave them out to use DHCP.
- `OTA_TRANSPORT=tftp` selects a plain TFTP transfer instead (no wolfSSL needed); the image is still verified by wolfBoot.

How an update runs:

1. A UDP datagram starting with `UPDATE` on port 7 asks the board to check for an update. The datagram carries no authority: the server address is the one built in.
2. The board opens TLS 1.3 to `OTA_SERVER_IP:4443` with the `SECP384R1MLKEM1024` hybrid key exchange, verifies the server certificate and its name (`ota-server.local`), and presents its own certificate.
3. `GET /version` returns the offered version as decimal text. If it is higher than `OTA_VERSION`, `GET /firmware.bin` is downloaded to RAM, written to the inactive slot, read back, and marked for wolfBoot. The board resets.
4. wolfBoot verifies the new image and boots it on probation. The new image confirms itself only after it has fetched `/version` from the server again; if it cannot within 30 seconds it resets and wolfBoot returns to the previous image.

The image on the server is the signed (and, if wolfBoot is built for it, encrypted) file produced by the wolfBoot `sign` tool. Because its header may be encrypted, the version on offer comes from the authenticated server, not from the image.

wolfBoot is built from its `versal_vmk180` configuration with ML-DSA-87 signatures, AES-256 encrypted images and two 4 MB slots:

```
cp config/examples/versal_vmk180.config .config
make SIGN=ML_DSA ML_DSA_LEVEL=5 IMAGE_SIGNATURE_SIZE=4627 IMAGE_HEADER_SIZE=12288 \
     ENCRYPT=1 ENCRYPT_WITH_AES256=1 CUSTOM_ENCRYPT_KEY=1 ENCRYPT_CACHE=0x08200000 \
     DUALBOOT_ROLLBACK_UNCONFIRMED=1 WOLFBOOT_PARTITION_SIZE=0x400000 \
     WOLFBOOT_PARTITION_UPDATE_ADDRESS=0xC00000 WOLFBOOT_PARTITION_SWAP_ADDRESS=0x1000000 \
     OBJS_EXTRA=/path/to/wolfip/src/port/amd/boards/versal/wolfboot_enckey.o
```

`wolfboot_enckey.c` gives wolfBoot the image key. Its key and IV are fixed, public demonstration values that match the key file passed to the `sign` tool; a product reads the key from eFuse, BBRAM or a PUF-wrapped store instead. The application is then converted to a binary, signed and encrypted (`enc_key.bin` holds the 32-byte key followed by the 16-byte IV):

```
aarch64-none-elf-objcopy -O binary app.elf app.bin
ML_DSA_LEVEL=5 IMAGE_HEADER_SIZE=12288 tools/keytools/sign --ml_dsa --sha384 --aes256 \
     --encrypt enc_key.bin app.bin wolfboot_signing_private_key.der 2
```

`host/https_server.c` is a small matching server (TLS 1.3, hybrid groups, client certificate required). Build it against a wolfSSL configured with `--enable-tls13 --enable-mlkem --enable-ecc CFLAGS=-DWOLFSSL_PQC_HYBRIDS` and run it as `https_server -p 4443 -d <docroot> -c host/certs`, with `version` and `firmware.bin` in the document root.

The certificates and keys written by `gen_certs.sh` are for demonstration only. With no real-time clock, certificate dates are checked against the build time plus uptime.

## Files

See `src/port/amd/README.md` for the shared-tree layout. This board dir
holds `board.h`, `board.c`, `board_gem.c`, `config.h`, the linker scripts
and `jtag/` (PDI-based JTAG loader). The differences listed in the table
above are the only substantive Versal-specific code.

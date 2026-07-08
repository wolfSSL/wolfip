# wolfIP on RealTek RTL8735B (AmebaPro2)

wolfIP TCP/IP stack running over the RTL8735B's native 10/100 Ethernet MAC (with its integrated Fast-Ethernet PHY), built inside the RealTek AmebaPro2 FreeRTOS SDK. Two demos, built from the same sources:

1. **Milestone 1** - DHCP client + raw TCP echo server (port 7). Proves the driver and stack.
2. **Milestone 2** - a wolfSSL TLS 1.2/1.3 client over a real wolfIP socket (add `--tls`).

## How it works

The RTL8735B has a native Ethernet MAC + integrated FEPHY (no external PHY). The vendor SDK exposes a frame-level mbed HAL (`ethernet_init/write/send/receive/read`) that owns the DMA descriptor rings and the D-cache clean/invalidate internally. This port is a thin adapter that binds wolfIP's two driver callbacks onto that HAL - no register-level MAC/DMA/MDIO code:

- wolfIP `send()` -> `ethernet_write()` + `ethernet_send()`
- wolfIP `poll()` -> `ethernet_receive()` + `ethernet_read()`

The whole stack runs in a single FreeRTOS task, so no wolfIP locking is required. RX is polled (milestone 1/2); the MAC IRQ hook only latches link up/down. The vendor lwIP layer is not used - wolfIP owns the interface.

## Files

| File | Purpose |
|------|---------|
| `wolfip_rtl8735b.c` / `.h` | wolfIP poll/send driver glue over the mbed Ethernet HAL |
| `main.c` | App: single task - MAC init, link/DHCP wait, echo server, optional TLS client |
| `config.h` | wolfIP build config (DHCP, socket counts, static-IP fallback) |
| `user_settings.h` | wolfSSL config for the TLS client (software crypto, ECDHE-ECDSA/AES-GCM) |
| `tls_client.c` / `.h` | Board-agnostic wolfIP TLS client (shared with the other ports) |
| `wolfip_eth.cmake` | SDK build integration (append wolfIP + optional wolfSSL sources) |
| `wolfip_cycle.sh` | Build -> flash -> read-console helper |

## Build and run

Prerequisites: the AmebaPro2 FreeRTOS SDK (`~/GitHub/ameba-rtos-pro2`), the ASDK 10.3.0 toolchain, and the hardware bench (Pi4 GPIO 21 boot-mode, J-Link nRESET for the CHIP_EN power-on reset, console on `/dev/ttyUSB5`). The system `arm-none-eabi-gcc` will not work - use the ASDK toolchain.

### SDK config

No SDK source edits are required. The non-TrustZone (`ntz`) app build already compiles the mbed Ethernet HAL: `DEVICE_ETHERNET=1` (device.h non-secure branch) and `CONFIG_MII_EN=1` (platform_conf_ntz.h). This port calls that HAL directly, so the vendor `CONFIG_ETHERNET`/lwIP path stays disabled (`CONFIG_ETHERNET=0`) and no lwIP is linked in.

### Hands-free cycle

```bash
cd ~/GitHub/wolfip/src/port/rtl8735b
./wolfip_cycle.sh            # milestone 1: DHCP + echo
./wolfip_cycle.sh --tls      # milestone 2: also build/run the TLS client
```

### Manual build

```bash
export PATH=~/ameba-pro2-workspace/asdk/asdk-10.3.0/linux/newlib/bin:$PATH
P=~/GitHub/ameba-rtos-pro2/project/realtek_amebapro2_v0_example
mkdir -p $P/component/example/wolfip_eth
cp main.c user_settings.h wolfip_eth.cmake $P/component/example/wolfip_eth/
cp main.c $P/src/main.c
cd $P/GCC-RELEASE && mkdir -p build && cd build
cmake .. -G"Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake \
  -DBUILD_FPGA=OFF -DBUILD_PXP=OFF -DEXAMPLE=wolfip_eth \
  -DWOLFIP_ROOT=~/GitHub/wolfip
make flash -j8               # -> build/flash_ntz.bin
~/.claude/skills/amebapro2-flash/amebapro2_flash.sh build/flash_ntz.bin
uart-monitor tail GENERIC_UART_ttyUSB5
```

For the TLS build add `-DWOLFIP_ENABLE_TLS=ON -DWOLFSSL_ROOT=~/GitHub/wolfssl`.

## Verify

- **M1:** the console prints the MAC, `Link up`, and `DHCP bound: ip=...`. From the host: `ping <ip>` and `nc <ip> 7` (whatever you type is echoed back).
- **M2:** additionally `TLS: connecting to ...` and `TLS: received N bytes` with the server's response. The TLS target defaults to an ECDSA host; override with `-DTLS_TARGET_IP`/`-DTLS_TARGET_HOST`/`-DTLS_TARGET_PORT`. Certificate verification is disabled in the demo (no RTC / CA store).

## Notes / limits

- Certificate validation is off (`WOLFSSL_VERIFY_NONE`) - demo only. Add a CA store and an RTC/`NO_ASN_TIME` removal for production.
- RX is polled today. An IRQ-driven path (push frames via `wolfIP_recv_ex()` from the RX thread) is a planned follow-up.
- Descriptor rings are placed in the reserved `__sram_rev_start__` SRAM region and packet buffers in the vendor DMA heap, mirroring the SDK's own `ethernet_mii` driver.

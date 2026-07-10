# Porting wolfIP to a new STM32

This tree is layered so a new STM32 wolfIP port is a small set of per-chip
files plus shared infrastructure. Existing ports: `stm32c5a3` (M33, TLS 1.3 +
DHUK), `stm32h753` (M7, TLS + HTTPS), `stm32h563` (M33, TLS + SSH + MQTT +
dot1x + FreeRTOS), `stm32f439` (M4, network only), `stm32n6` (M55, network
only).

## Shared -- reuse as-is

| File | What it gives you |
|------|-------------------|
| `src/port/stm32/stm32_eth.c` / `.h` | Synopsys DWC GMAC MAC+DMA+PHY driver for H5/H7/N6 (and C5, via a one-line `STM32C5 -> STM32H5` alias). ETH1 at `0x40028000` on H5/C5. |
| `src/port/stm32/wolfssl.mk` | `WOLFSSL_ROOT`/`WOLFMQTT_ROOT` defaults, the `WOLFSSL_SRCS` TLS-1.3 source list, the optional `WOLFSSL_LOG_SRCS` (logging/error/wc_encrypt) group, and the `$(WOLFSSL_ROOT)/%.o` relaxed-warning rule. `include` it from a port Makefile. |
| `src/port/wolfssl_io.c` | wolfIP <-> wolfSSL I/O callbacks (EAGAIN -> WANT_READ/WRITE, `-1` -> CONN_CLOSE). |
| `src/port/tls_client.c` / `.h` | Shared TLS 1.3 client state machine. Build knobs (per-port `-D`): `TLS_CLIENT_MUTUAL_AUTH` (present a client cert from the port's `tls_certs.h`), `ENABLE_DHUK_KEY` (sign CertificateVerify via the DHUK PK callback), `TLS_CLIENT_CIPHER` (force one suite), `TLS_CLIENT_SETTLE_POLLS` (post-connect settle, default 10). Without `MUTUAL_AUTH` it is a plain one-way client (SNI via `tls_client_set_sni()`). |
| `src/port/certs.h` | Embedded test certificates (for the HTTPS/server ports). |
| `src/wolfip.c` | The stack itself. |

## Per-chip -- supply these

| File | Notes |
|------|-------|
| `startup.c` (+ `ivt.c`) | Vendor vector table + reset. Genuinely per-silicon (different peripheral IRQ set). C5A3 folds the full M33 vector table into `startup.c` (no separate `ivt.c`). |
| `target.ld` | Memory map (flash/RAM addresses + sizes). Add an `.eth_buffers` output section in RAM for the GMAC descriptors + RX/TX buffers. |
| `main.c` | The per-chip register sequences: `clock_init`, `uart_init`, `eth_gpio_init` (RMII pinmux + SYSCFG/SBS PHY-interface select + RCC ETH gates), `rng_init`. Plus the wolfIP init + poll loop (mostly copyable between ports). |
| `config.h` | wolfIP sizing (sockets, buffers, static IP). |
| `user_settings.h` | wolfSSL config: the shared TLS-1.3 base + a per-chip HW-crypto arm (`STM32_HASH` / `STM32_CRYPTO` / `WOLFSSL_STM32_PKA` / RNG, gated on the chip define). |
| `Makefile` | Thin: CPU flags, device `-D`, includes, `include ../stm32/wolfssl.mk`, board sources, feature source lists, flash command. |

## Makefile pattern

```make
CFLAGS := -mcpu=cortex-mXX ... -D<CHIP>
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS)) -Wno-unused-variable -Wno-unused-function
include $(ROOT)/src/port/stm32/wolfssl.mk         # WOLFSSL_SRCS + %.o rule + defaults
...
ifeq ($(ENABLE_TLS),1)
  WOLFSSL_SRCS += $(WOLFSSL_LOG_SRCS)              # unless you strip logging/error to save flash
  SRCS += $(WOLFSSL_SRCS)
endif
```

- A port that needs feature defines on the wolfSSL objects (e.g. SSH/dot1x) sets `WOLFSSL_EXTRA_DEFS` -- the shared `%.o` rule appends it (see `stm32h563/Makefile`).
- Keep `all:`/`clean:`/`size:`/`flash:` in the port; `wolfssl.mk` intentionally defines only variables and the `%.o` pattern rule so it never hijacks the default goal.

## New-port checklist (things that bite)

- **`_sbrk` must use the linker `.heap` region**, not `_ebss.._estack`. On a port whose linker places `.eth_buffers` after `.bss`, an `_ebss`-based heap hands out malloc memory that overlaps the Ethernet DMA buffers, and packet DMA silently corrupts heap objects (seen on C5A3: garbage `WOLFSSL_CTX->method` -> bus fault deep in TLS).
- **Add the port to the root `Makefile` cppcheck suppression list** (`comparePointers` for `startup.c`/`syscalls.c`, and `unknownMacro` for a CMSIS vendor `startup.c`). A cleaner alternative for new code: cast the `_sbrk` bounds compare to `uintptr_t` so no `comparePointers` suppression is needed.
- **RMII alternate-function numbers are not uniform** -- check each pin against the CubeMX/HAL board example (on C5A3, RXD0/RXD1 are AF12/AF13 while the rest are AF10). A wrong AF on an RX pin leaves the link up (MDIO works) but drops all RX.
- **DMA buffers must be in DMA-reachable RAM** (not DTCM on H7); place them via the `.eth_buffers` section.
- **Wire MSPLIM** to the linker's real stack-limit symbol (`PROVIDE(__STACK_LIMIT = __StackLimit)` if the CMSIS startup uses `__STACK_LIMIT`) so a stack overflow faults cleanly instead of corrupting the heap.
- The `../wolfssl` object tree is shared: ports at different FP ABIs (hard vs soft float) clobber each other's `.o` files. `make clean` (or delete `$(WOLFSSL_ROOT)/**/*.o`) between such builds.

## Shared TLS client

`tls_client.c`/`.h` moved to `src/port/` (see the shared table above). The three
TLS ports now compile the single `$(ROOT)/src/port/tls_client.c` and select
behavior with `-D` knobs: `stm32c5a3` sets `TLS_CLIENT_MUTUAL_AUTH` +
`TLS_CLIENT_CIPHER` (+ `ENABLE_DHUK_KEY`) for its mutual-auth DHUK demo, while
`stm32h753`/`stm32h563` build it as a plain one-way client (H753 keeps its
historical `TLS_CLIENT_SETTLE_POLLS=100`). C5A3's mutual-auth + DHUK build is
verified on hardware; H753/H563 are build-verified (boards not testable here --
no H753 on the bench, H563 is provisioned TZEN=1).

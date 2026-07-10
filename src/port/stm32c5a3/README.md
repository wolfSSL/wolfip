# wolfIP on STM32C5A3ZG (NUCLEO-C5A3ZG)

Bare-metal wolfIP TCP/IP port for the STMicro STM32C5A3ZG (Cortex-M33F, no
TrustZone), with a TLS 1.3 mutual-auth client whose long-term ECDSA identity
key is protected by the STM32 DHUK (Device Hardware Unique Key) crypto
callback: the private scalar is unwrapped inside the SAES block and signed on
the hardware PKA, so it never appears in software.

## Status

All configurations validated on hardware (NUCLEO-C5A3ZG):

- Network: DHCP + ICMP ping + TCP echo on port 7.
- TLS 1.3 mutual-auth client: `TLS_AES_128_GCM_SHA256`, peer verifies the device client certificate.
- DHUK identity key in TLS: CertificateVerify signed through the callback (SAES unwrap -> HW PKA).

## Hardware

- MCU: Cortex-M33F @ 144 MHz (HSE 48 MHz -> PSI -> PSIS), 1 MB flash, 256 KB SRAM. No TrustZone (single image).
- Ethernet: on-chip Synopsys DWC GMAC (RMII), shared driver `../stm32/stm32_eth.c`.
- Crypto: SAES, PKA (V2, sign-only), HASH, RNG.

RMII pin map (all AF10 unless noted):

| Signal    | Pin  | Note                         |
|-----------|------|------------------------------|
| REF_CLK   | PA1  |                              |
| MDC       | PC1  |                              |
| MDIO      | PE12 | not PA2 (PA2 = USART2 TX)    |
| CRS_DV    | PD1  |                              |
| RXD0      | PC4  | **AF12** (not AF10)          |
| RXD1      | PC5  | **AF13** (not AF10)          |
| TX_EN     | PG11 |                              |
| TXD0      | PG13 |                              |
| TXD1      | PG12 |                              |

Console: USART2 PA2(TX)/PA3(RX) AF7, 115200 8N1 over the ST-LINK VCP.

## Build

```
make                                          # network only (DHCP + ping + TCP echo)
make ENABLE_TLS_CLIENT=1                        # + TLS 1.3 mutual-auth client (software identity key)
make ENABLE_TLS_CLIENT=1 ENABLE_DHUK_KEY=1      # + identity key signed via the DHUK callback
```

The TLS builds need the wolfSSL branch that carries the STM32C5 bare-crypto +
DHUK port; point `WOLFSSL_ROOT` at it (defaults to the sibling `../wolfssl-c5tls`
for those builds). The wolfSSL/wolfCrypt source list and build rules are shared
from `../stm32/wolfssl.mk`.

If your shell presets `CC` to the host compiler, pass `CC=arm-none-eabi-gcc`.

Approx flash usage (1 MB): network 3.0%, TLS 21.2%, TLS+DHUK 21.9%.

## Flash

STM32CubeProgrammer over SWD (pyocd / st-flash do not support C5; the debug AP
is AP2, so use under-reset connect):

```
make flash
# = STM32_Programmer_CLI -c port=swd sn=<ST-LINK-SN> mode=UR -e all -d app.bin 0x08000000 -v -rst
```

## TLS test

The device is the client; run an OpenSSL server on the host that requires and
verifies the client certificate:

```
cd tls-certs
openssl s_server -accept 11111 -tls1_3 -cert server.pem -key server.key.pem \
    -Verify 1 -CAfile ca.pem -www
```

Set the target in `config.h` (`TLS_SERVER_IP` / `TLS_SERVER_PORT`). On success
the device logs `TLS Client: Passed!` and the server logs `verify return:1` for
`CN = stm32c5a3-client`.

## Test certificates

`tls_certs.h` (embedded in the firmware, all public material) is committed; the
host server material `tls-certs/` is git-ignored (it holds a throwaway test
key). Both come from `gen_certs.py`. The client identity keypair is the public
NIST P-256 CAVP vector in `identity_key.h`; the CA and server are fixed-scalar
test keys. To (re)generate before running the TLS test:

```
python3 gen_certs.py     # writes tls_certs.h AND tls-certs/{ca,server,server.key}.pem
make ENABLE_TLS_CLIENT=1 ENABLE_DHUK_KEY=1 && make flash
```

ECDSA cert DER is not byte-reproducible, so regenerating rewrites `tls_certs.h`
too -- rebuild + reflash so the device cert matches the fresh host CA.

## Hardware gotchas (see the inline comments)

- RXD0/RXD1 use AF12/AF13, not AF10 -- AF10 there silently kills RX (link stays up via MDIO, no frames received).
- The RNG clock-error detector (`CR.CED`) false-trips on the 48 MHz CK48 clock; it is disabled (`WC_STM32_RNG_CED_DISABLE`).
- `_sbrk` uses the linker `.heap` region -- an `_ebss.._estack` heap would overlap the Ethernet DMA buffers and be corrupted by packet DMA.
- C5 PKA is sign-only: ECDSA verify and ephemeral ECDHE run in software (Config A).

## Out of scope

- Config B (`WOLF_CRYPTO_CB_ONLY_ECC`, route ECDHE through the callback to strip software ECC) -- needs wolfSSL-side ECDH callback work.
- wolfBoot secure-boot chainload (this board is supported by wolfBoot `config/examples/stm32c5.config`).

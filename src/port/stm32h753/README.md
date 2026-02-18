# wolfIP STM32H753ZI Port

This port provides a bare-metal wolfIP TCP/IP stack implementation for the
STM32H753ZI microcontroller (NUCLEO-H753ZI board).

## Features

- **TCP/IP Stack**: Full wolfIP stack with TCP, UDP, ICMP, ARP, DHCP
- **TLS 1.3 Client**: Connect to HTTPS servers using wolfSSL
- **Hardware Acceleration**: STM32 HASH/HMAC, AES, and RNG
- **Ethernet**: RMII interface with LAN8742 PHY
- **Bare Metal**: No RTOS required

## Hardware Requirements

- NUCLEO-H753ZI development board (or compatible STM32H753ZI board)
- Ethernet cable connected to a network with DHCP server
- USB cable for ST-Link programming and debug UART

## Pin Configuration (NUCLEO-H753ZI RMII)

| Pin  | Function     | Description        |
|------|--------------|--------------------|
| PA1  | ETH_REF_CLK  | 50MHz reference    |
| PA2  | ETH_MDIO     | PHY management     |
| PA7  | ETH_CRS_DV   | Carrier sense      |
| PC1  | ETH_MDC      | PHY clock          |
| PC4  | ETH_RXD0     | Receive data 0     |
| PC5  | ETH_RXD1     | Receive data 1     |
| PB13 | ETH_TXD1     | Transmit data 1    |
| PG11 | ETH_TX_EN    | Transmit enable    |
| PG13 | ETH_TXD0     | Transmit data 0    |
| PD8  | USART3_TX    | Debug output       |

## Building

### Prerequisites

- ARM GCC toolchain (`arm-none-eabi-gcc`)
- wolfSSL (cloned alongside wolfIP, or set `WOLFSSL_ROOT`)

### Build Commands

```bash
# Basic TCP echo server (no TLS)
make

# With TLS 1.3 client support
make ENABLE_TLS=1

# With TLS + HTTPS server
make ENABLE_TLS=1 ENABLE_HTTPS=1

# Clean build
make clean

# Show memory usage
make size
```

### Memory Usage

| Configuration      | Flash    | RAM (static) |
|-------------------|----------|--------------|
| TCP Echo only     | ~50 KB   | ~30 KB       |
| + TLS 1.3 Client  | ~180 KB  | ~100 KB      |
| + HTTPS Server    | ~200 KB  | ~110 KB      |

## Flashing

Using ST-Link:

```bash
make flash
# or
st-flash write app.bin 0x08000000
```

## Testing

### Serial Debug Output

Connect to the ST-Link VCP at 115200 baud:

```bash
screen /dev/ttyACM0 115200
# or
minicom -D /dev/ttyACM0 -b 115200
```

### TCP Echo Test

After the device boots and shows its IP address:

```bash
nc <device-ip> 7
# Type text and press Enter - it will be echoed back
```

### TLS Client Test

When built with `ENABLE_TLS=1`, the device automatically connects to Google
(142.250.189.174:443) after 5 seconds and performs an HTTPS GET request.
The response is printed on the serial console.

## Memory Map

| Region       | Address      | Size   | Usage                      |
|--------------|--------------|--------|----------------------------|
| FLASH        | 0x08000000   | 1 MB   | Code and constants         |
| D1 AXI-SRAM  | 0x24000000   | 512 KB | Main RAM (heap, stack)     |
| D2 SRAM1     | 0x30000000   | 128 KB | Ethernet DMA buffers       |

Note: Ethernet DMA cannot access DTCM (0x20000000), so we use AXI-SRAM and
D2 SRAM for DMA-accessible buffers.

## Hardware Acceleration

This port leverages STM32H753 hardware crypto accelerators:

- **STM32_HASH**: Hardware SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **STM32_HMAC**: Hardware HMAC (accelerates TLS PRF operations)
- **STM32_CRYPTO**: Hardware AES (ECB, CBC, CTR, GCM modes)
- **STM32_RNG**: Hardware random number generator

Enable these in `user_settings.h`:

```c
#define WOLFSSL_STM32H7
#define WOLFSSL_STM32_CUBEMX
#define STM32_HASH
#define STM32_HMAC
#define STM32_CRYPTO
#define STM32_RNG
```

## Troubleshooting

### No serial output
- Check USB connection to ST-Link
- Verify baud rate is 115200
- Ensure PD8 is configured as USART3_TX

### No Ethernet link
- Check Ethernet cable is connected
- Verify PHY is detected (debug output shows PHY address)
- Check RMII clock is running (PA1)

### DHCP timeout
- Ensure network has a DHCP server
- Check network cable and switch port
- Try static IP configuration (set `WOLFIP_ENABLE_DHCP=0` in config.h)

### TLS handshake fails
- Ensure wolfSSL is properly configured
- Check that SNI is set for the target server
- Verify clock is accurate enough for certificate validation

## File Structure

```
stm32h753/
├── Makefile          # Build system
├── README.md         # This file
├── config.h          # wolfIP configuration
├── user_settings.h   # wolfSSL configuration
├── target.ld         # Linker script
├── startup.c         # Cortex-M7 startup code
├── ivt.c             # Interrupt vector table
├── syscalls.c        # Newlib stubs
├── main.c            # Application entry point
├── stm32h7_eth.c     # Ethernet MAC/PHY driver
├── stm32h7_eth.h     # Ethernet driver header
├── tls_client.c      # TLS 1.3 client
└── tls_client.h      # TLS client header
```

## License

Copyright (C) 2024 wolfSSL Inc.

This project is licensed under GPLv3. See the wolfIP LICENSE file for details.

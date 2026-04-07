# wolfHAL Port for wolfIP

Generic wolfIP port that uses the wolfHAL Ethernet API (`whal_Eth` /
`whal_EthPhy`). Users create a wolfHAL board and the port handles the
rest — bridging wolfHAL's Ethernet MAC/PHY drivers to wolfIP's
link-layer device interface.

## Supported Boards

| Board | MCU | PHY | Directory |
|-------|-----|-----|-----------|
| NUCLEO-H563ZI | STM32H563ZI | LAN8742A | `boards/stm32h563zi_nucleo` |

## Directory Structure

```
src/port/wolfHAL/
├── Makefile            # Top-level build: make BOARD=<board_name>
├── main.c              # Generic main: board_init -> wolfhal_eth_init -> wolfIP_poll loop
├── wolfhal_eth.h       # Port API and wolfhal_eth_ctx struct
├── wolfhal_eth.c       # Bridges wolfIP_ll_dev poll/send to whal_Eth_Recv/whal_Eth_Send
└── boards/
    └── <board_name>/
        ├── board.mk    # Toolchain, CFLAGS, wolfHAL driver sources
        ├── board.h     # Board API declarations and device externs
        ├── board.c     # Clock, GPIO, Ethernet, PHY, UART, timer setup
        ├── startup.c   # Reset_Handler: copies .data, zeros .bss, calls main()
        ├── ivt.c       # Interrupt vector table
        ├── syscalls.c  # libc stubs (_write, _sbrk, etc.)
        └── linker.ld   # Memory layout (FLASH/RAM regions)
```

## Building

```
cd src/port/wolfHAL
make BOARD=stm32h563zi_nucleo
```

Override the wolfHAL location (defaults to `../../../wolfHAL` relative to
the wolfip root, i.e. a sibling directory):

```
make BOARD=stm32h563zi_nucleo WOLFHAL_ROOT=/path/to/wolfHAL
```

Override IP configuration or MAC address at build time:

```
make BOARD=stm32h563zi_nucleo \
    CFLAGS+='-DWOLFIP_IP=\"10.0.0.2\" -DWOLFIP_NETMASK=\"255.255.255.0\" -DWOLFIP_GW=\"10.0.0.1\"'
```

```
make BOARD=stm32h563zi_nucleo \
    CFLAGS+='-DBOARD_MAC_ADDR={0x02,0xAA,0xBB,0xCC,0xDD,0xEE}'
```

## Adding a New Board

Create a new directory under `boards/` with the following files:

### board.h

Must declare the following:

#### Required Device Externs

| Variable | Type | Description |
|----------|------|-------------|
| `g_whalEth` | `whal_Eth` | Initialized Ethernet MAC device |
| `g_whalEthPhy` | `whal_EthPhy` | Initialized Ethernet PHY device |
| `g_whalUart` | `whal_Uart` | Initialized UART device (used by `_write` syscall for printf) |
| `g_whalRng` | `whal_Rng` | Initialized RNG device (used by `wolfIP_getrandom`) |

These names are required — `main.c`, `wolfhal_eth.c`, and `syscalls.c`
reference them directly.

#### Required Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `board_init` | `whal_Error board_init(void)` | Initialize all board hardware. Must call `whal_Eth_Init`, `whal_EthPhy_Init`, `whal_Uart_Init`, and start the system timer before returning. Returns `WHAL_SUCCESS` on success. |
| `board_deinit` | `whal_Error board_deinit(void)` | Tear down board hardware in reverse order. |
| `board_get_tick` | `uint32_t board_get_tick(void)` | Return a millisecond tick counter. Used by `wolfhal_eth_init` for link timeout and by `wolfIP_poll` for stack timing. |

### board.c

Implements the functions above. Typical `board_init` sequence:

1. Initialize clocks (PLL, peripheral clocks)
2. Initialize GPIO (UART pins, Ethernet pins)
3. Initialize UART (`whal_Uart_Init`)
4. Initialize Ethernet MAC (`whal_Eth_Init`)
5. Initialize Ethernet PHY (`whal_EthPhy_Init`)
6. Initialize and start system timer

The `whal_Eth` device must have its `macAddr` field set — this is
where wolfIP reads the interface MAC address from.

### board.mk

Provides build configuration. Must set:

| Variable | Description |
|----------|-------------|
| `WOLFHAL_ROOT` | Path to wolfHAL (use `?=` so it's overridable) |
| `GCC` | Cross-compiler path (e.g. `arm-none-eabi-gcc`) |
| `OBJCOPY` | Objcopy tool |
| `CFLAGS` | Compiler flags (architecture, warnings, includes) |
| `LDFLAGS` | Linker flags |
| `LDLIBS` | Libraries to link (libc, libgcc, etc.) |
| `LINKER_SCRIPT` | Path to the board's linker script |
| `BOARD_SOURCE` | List of board + wolfHAL driver source files |

`BOARD_SOURCE` must include at minimum:
- `startup.c`, `ivt.c`, `board.c`, `syscalls.c` from the board directory
- wolfHAL drivers: `eth/eth.c`, `eth/<platform>_eth.c`,
  `eth_phy/eth_phy.c`, `eth_phy/<phy>.c`, `clock/clock.c`,
  `clock/<platform>_rcc.c`, `gpio/gpio.c`, `gpio/<platform>_gpio.c`,
  `timer/timer.c`, `timer/systick.c`, `uart/uart.c`,
  `uart/<platform>_uart.c`, `rng/rng.c`,
  `rng/<platform>_rng.c`

### syscalls.c

Must provide:
- Standard libc stubs: `_write`, `_read`, `_sbrk`, `_close`, `_fstat`,
  `_isatty`, `_lseek`, `_exit`, `_kill`, `_getpid`
- `_write` should route to `whal_Uart_Send(&g_whalUart, ...)` so that
  `printf` outputs to UART
- `uint32_t wolfIP_getrandom(void)` is provided by `main.c` using
  `whal_Rng_Generate(&g_whalRng, ...)`

### startup.c, ivt.c, linker.ld

Standard bare-metal files for your target architecture. See the
`stm32h563zi_nucleo` board for a reference implementation.

## Port API

The port exposes a single function:

```c
#include "wolfhal_eth.h"

struct wolfhal_eth_ctx ctx = {
    .eth = &g_whalEth,
    .phy = &g_whalEthPhy,
};

int ret = wolfhal_eth_init(wolfIP_getdev(ipstack), &ctx);
```

`wolfhal_eth_init` will:
1. Poll `whal_EthPhy_GetLinkState` until link comes up (5s timeout,
   configurable via `WOLFHAL_ETH_LINK_TIMEOUT_MS`)
2. Start the MAC with negotiated speed/duplex
3. Copy `eth->macAddr` to the wolfIP device
4. Register poll/send callbacks that bridge to `whal_Eth_Recv`/`whal_Eth_Send`

## Naming Conventions

- All port functions and variables use `snake_case`
- Board functions use `board_` prefix: `board_init`, `board_get_tick`
- Port functions use `wolfhal_` prefix: `wolfhal_eth_init`
- wolfHAL API calls retain their own naming (`whal_Eth_Init`, etc.)
- Global device instances use `g_whal` prefix: `g_whalEth`, `g_whalEthPhy`, `g_whalUart`, `g_whalRng`
- Macros use `UPPER_SNAKE_CASE`

# wolfHAL Ethernet bridge for wolfIP

Generic, board-agnostic glue between wolfIP's link-layer device interface
and the wolfHAL Ethernet API (`whal_Eth` / `whal_EthPhy`). This directory
holds only the bridge:

```
src/port/wolfHAL/
├── wolfhal_eth.h   # Port API and wolfhal_eth_ctx struct
└── wolfhal_eth.c   # Bridges wolfIP_ll_dev poll/send to whal_Eth_Recv/whal_Eth_Send
```

There is no platform code here — the bridge works with any board that
provides a configured `whal_Eth` and `whal_EthPhy`. Board bringup
(clocks, GPIO, MAC/PHY/RNG/UART init) and the bare-metal scaffolding
live in the chip port under `src/port/<chip>/boards/<board>/`.

## Reference integration

`src/port/stm32h563/` integrates this bridge as an opt-in driver backend
for the NUCLEO-H563ZI board:

```
make -C src/port/stm32h563 ENABLE_WOLFHAL=1
```

The build requires `TZEN=0` (the default) and `FREERTOS=0` (the default);
the Makefile errors out otherwise. `board_init()` programs the PLL
directly, which conflicts with the wolfBoot-launched non-secure clock
flow used by `TZEN=1`, and the wolfHAL SysTick driver owns the SysTick
handler that FreeRTOS also needs.

`ENABLE_WOLFHAL=1` selects `boards/stm32h563zi_nucleo/` (its own
`startup.c`/`ivt.c`/`syscalls.c`/`linker.ld` plus `board.c`/`board.h`/`board.mk`),
pulls the wolfHAL STM32H5 driver TUs from a sibling wolfHAL checkout
(`WOLFHAL_ROOT ?= ../wolfHAL`), and compiles the port's `main.c` against
wolfHAL drivers instead of the hand-rolled bare-metal ones.

## Port API

```c
#include "wolfhal_eth.h"

struct wolfhal_eth_ctx ctx = {
    .eth = &g_whalEth,     /* configured by board_init() */
    .phy = &g_whalEthPhy,
};

int ret = wolfhal_eth_init(wolfIP_getdev(ipstack), &ctx);
```

`wolfhal_eth_init` will:
1. Poll `whal_EthPhy_GetLinkState` until link comes up (5s timeout,
   configurable via `WOLFHAL_ETH_LINK_TIMEOUT_MS`).
2. Start the MAC with the negotiated speed/duplex.
3. Copy `eth->macAddr` to the wolfIP device.
4. Register poll/send callbacks that bridge to `whal_Eth_Recv`/`whal_Eth_Send`.

## What a board must provide

The bridge needs the hardware already brought up. A board's `board.c`
(see `src/port/stm32h563/boards/stm32h563zi_nucleo/board.c`) must, before
`wolfhal_eth_init` is called:

- Initialize clocks and GPIO, then call `whal_Eth_Init` / `whal_EthPhy_Init`
  (typically from `board_init()`).
- Set the `whal_Eth` device's `macAddr` field — wolfIP reads the interface
  MAC from there.
- Expose the devices the port references by name: `g_whalEth`, `g_whalEthPhy`,
  and (for the port's `printf`/RNG hooks) `g_whalUart`, `g_whalRng`.
- Provide `uint32_t board_get_tick(void)` — a millisecond counter used both
  for the `wolfhal_eth_init` link timeout and for `wolfIP_poll` timing.

# wolfIP AURIX TC4xx port

Ethernet driver for GETH0 of Infineon AURIX TC4xx microcontrollers, in RMII mode through the on-chip HSPHY, built on Infineon's iLLD. It powers and configures the HSPHY, brings up the MAC and an external clause-22 PHY, runs one receive and one transmit DMA ring, and fills in a `struct wolfIP_ll_dev`. It is RTOS-agnostic: the driver has no main loop, startup code or scheduler dependency.

Tested on the KIT_TC4D7_LITE (TC4D7, TI DP83825I PHY) at 100 Mbit/s full duplex.

## Files

- `tc4xx_eth.h` - public API.
- `tc4xx_eth.c` - HSPHY bring-up, MAC, MDIO, DMA rings, the wolfIP poll/send callbacks and the optional receive interrupt.
- `tc4xx_eth_board.h` - pin, PHY and timeout defaults for the TC4D7 Lite Kit, all overridable.
- `../common/aurix_phy.h` - clause-22 PHY detect, reset, auto-negotiation and link resolution, shared by the two AURIX ports.

## Requirements

- Infineon iLLD for TC4xx, from [illd_release_tc4x](https://github.com/Infineon/illd_release_tc4x) or AURIX Development Studio. Tested with 2.6.1 and v2.7.0. The driver uses the Geth, Hsphy, Pms, Vmt, Clock, Stm, Port and Cpu modules. The iLLD is not part of wolfIP and has its own license.
- A TriCore compiler. Tested with `tricore-elf-gcc` 13.4.1.
- From the application:
  - clock and startup setup (`Ifx_Cfg.h` and the iLLD startup, as in any ADS project)
  - a wolfIP `config.h` with `LINK_MTU` of at most 1536
  - `wolfIP_getrandom()`
  - a context that calls `wolfIP_poll()`

The HSPHY supply rails and the MAC SRAM list are those of the TC4Dx. Other TC4x derivatives may need changes there.

## Usage

```c
#include "config.h"
#include "wolfip.h"
#include "tc4xx_eth.h"

struct wolfIP *stack;

wolfIP_init_static(&stack);
if (tc4xx_eth_init(wolfIP_getdev(stack), NULL) != TC4XX_ETH_OK) {
    /* TC4XX_ETH_ENOPHY, TC4XX_ETH_ENOCLK, TC4XX_ETH_EIO, or TC4XX_ETH_EINVAL
       for a NULL ll or a second call */
}
wolfIP_ipconfig_set(stack, atoip4("192.168.1.10"), atoip4("255.255.255.0"),
                    atoip4("192.168.1.1"));

for (;;) {
    wolfIP_poll(stack, now_ms());
    /* Every second or so, to follow cable changes: */
    (void)tc4xx_eth_link_update();
}
```

`tc4xx_eth_init()` waits up to `TC4XX_ETH_LINK_TIMEOUT_MS` for auto-negotiation and returns success without a link, so the board still comes up with the cable out. Call `tc4xx_eth_link_update()` periodically so the MAC follows the negotiated speed and duplex when the link comes up later.

## Configuration

Define any of these in `CFLAGS` or in the application's `config.h`, which the driver includes first.

| Macro | Default | Meaning |
|---|---|---|
| `TC4XX_ETH_PIN_*` | TC4D7 Lite Kit | RMII and MDIO pins from `IfxGeth_PinMap.h` |
| `TC4XX_ETH_PHY_ADDR` | `0` | PHY address tried first; the bus is scanned if it does not answer |
| `TC4XX_ETH_DEFAULT_MAC` | `02:00:00:00:00:01` | used when `tc4xx_eth_init()` gets `mac == NULL`; every board on a network needs its own |
| `TC4XX_ETH_PHY_TIMEOUT_MS` | `1000` | how long to wait for the PHY to leave reset |
| `TC4XX_ETH_LINK_TIMEOUT_MS` | `5000` | how long `tc4xx_eth_init()` waits for a link, checked every 10 ms; `0` does not wait |
| `TC4XX_ETH_DELAY_MS(ms)` | CPU0 STM busy-wait | delay used during bring-up; an override must sleep at least `ms` milliseconds, so convert to ticks and round up |
| `TC4XX_ETH_RING_ATTR` | empty | attribute placing the rings, e.g. `__attribute__((section(".gethRing")))` |
| `TC4XX_ETH_RX_IRQ` | `0` | `1` enables the receive interrupt |
| `TC4XX_ETH_RX_IRQ_PRIO` | none | its priority; required with `TC4XX_ETH_RX_IRQ` and unique on the servicing CPU |
| `TC4XX_ETH_RX_IRQ_TOS` | `IfxSrc_Tos_cpu0` | CPU servicing the interrupt |
| `TC4XX_ETH_RX_IRQ_VECTAB` | `0` | vector table of that CPU |

## Memory

The rings take about 24.8 KB: eight receive and eight transmit descriptors (fixed by the iLLD's `IFXGETH_MAX_*_DESCRIPTORS`) with a 1536-byte buffer each. The GETH DMA must reach them through a global address without a cache in between.

- **DSPR.** The default, plain `.bss` in a CPU's DSPR, works with the standard ADS startup.
- **LMU.** Use a non-cached segment, and grant the GETH DMA masters access in that region's APU before calling `tc4xx_eth_init()`. At reset an LMU region admits only CPU0 and debug. On the TC4Dx the GETH tags are 48 to 51, which sit in the upper access-enable word (`WRB`/`RDB`). A missing grant does not trap: the MAC initialises, the PHY answers, and no frame ever moves.

## Receive interrupt

Without `TC4XX_ETH_RX_IRQ` the driver is purely polled. With it, the iLLD enables the DMA receive interrupt, and the handler clears it and calls the function passed to `tc4xx_eth_set_rx_notify()`, typically to wake the task that runs `wolfIP_poll()`. The callback runs in interrupt context and must not call wolfIP or the driver. The interrupt only shortens the wait: `wolfIP_poll()` handles a bounded number of frames per call and also runs wolfIP's timers, so the task must still wake periodically, not only on the callback. Otherwise frames left in the ring when that bound is reached wait until something else wakes it. The priority must be unique on the servicing CPU.

## Threading

The poll and send callbacks serialise their ring access by briefly disabling interrupts, so frames may be sent from a different task than the one polling. That only excludes code on the same CPU, so every driver entry point must run on one core. `tc4xx_eth_mdio_read()`, `tc4xx_eth_mdio_write()` and `tc4xx_eth_link_update()` are not serialised against each other and belong to a single context. As with every wolfIP port, only one context may call into the stack at a time.

## Limitations

- GETH0 port 0 only, one DMA channel per direction.
- RMII only, 10 and 100 Mbit/s.
- No checksum offload: wolfIP computes and verifies all checksums itself.
- Not built by CI, which has neither a TriCore compiler nor the iLLD.

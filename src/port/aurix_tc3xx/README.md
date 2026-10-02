# wolfIP AURIX TC3xx port

Ethernet driver for the GETH MAC of Infineon AURIX TC3xx microcontrollers, in RMII mode, built on Infineon's iLLD. It brings up the MAC and an external clause-22 PHY, runs one receive and one transmit DMA ring, and fills in a `struct wolfIP_ll_dev`. It is RTOS-agnostic: the driver has no main loop, startup code or scheduler dependency.

Tested on the KIT_A2G_TC375_LITE (TC375, TI DP83825I PHY) at 100 Mbit/s full duplex.

## Files

- `tc3xx_eth.h` - public API.
- `tc3xx_eth.c` - MAC, MDIO, DMA rings, the wolfIP poll/send callbacks and the optional receive interrupt.
- `tc3xx_eth_board.h` - pin, PHY and timeout defaults for the TC375 Lite Kit, all overridable.
- `../common/aurix_phy.h` - clause-22 PHY detect, reset, auto-negotiation and link resolution, shared by the two AURIX ports.

## Requirements

- Infineon iLLD for TC3xx, from [illd_release_tc3x](https://github.com/Infineon/illd_release_tc3x) or AURIX Development Studio. Tested with V1.20.0 and V1.22.0. The driver uses the Geth, Stm, Scu, Src, Port and Cpu modules. The iLLD is not part of wolfIP and has its own license.
- A TriCore compiler. Tested with `tricore-elf-gcc` 13.4.1.
- From the application:
  - clock and startup setup (`Ifx_Cfg.h` and the iLLD startup, as in any ADS project)
  - a wolfIP `config.h` with `LINK_MTU` of at most 1536
  - `wolfIP_getrandom()`
  - a context that calls `wolfIP_poll()`

## Usage

```c
#include "config.h"
#include "wolfip.h"
#include "tc3xx_eth.h"

struct wolfIP *stack;

wolfIP_init_static(&stack);
if (tc3xx_eth_init(wolfIP_getdev(stack), NULL) != TC3XX_ETH_OK) {
    /* TC3XX_ETH_ENOPHY, TC3XX_ETH_ENOCLK, TC3XX_ETH_EIO, or TC3XX_ETH_EINVAL
       for a NULL ll or a second call */
}
wolfIP_ipconfig_set(stack, atoip4("192.168.1.10"), atoip4("255.255.255.0"),
                    atoip4("192.168.1.1"));

for (;;) {
    wolfIP_poll(stack, now_ms());
    /* Every second or so, to follow cable changes: */
    (void)tc3xx_eth_link_update();
}
```

`tc3xx_eth_init()` waits up to `TC3XX_ETH_LINK_TIMEOUT_MS` for auto-negotiation and returns success without a link, so the board still comes up with the cable out. Call `tc3xx_eth_link_update()` periodically so the MAC follows the negotiated speed and duplex when the link comes up later.

## Configuration

Define any of these in `CFLAGS` or in the application's `config.h`, which the driver includes first.

| Macro | Default | Meaning |
|---|---|---|
| `TC3XX_ETH_MODULE` | `MODULE_GETH` | GETH instance |
| `TC3XX_ETH_PIN_*` | TC375 Lite Kit | RMII and MDIO pins from `IfxGeth_PinMap.h` |
| `TC3XX_ETH_PHY_ADDR` | `0` | PHY address tried first; the bus is scanned if it does not answer |
| `TC3XX_ETH_DEFAULT_MAC` | `02:00:00:00:00:03` | used when `tc3xx_eth_init()` gets `mac == NULL`; every board on a network needs its own |
| `TC3XX_ETH_PHY_TIMEOUT_MS` | `1000` | how long to wait for the PHY to leave reset |
| `TC3XX_ETH_LINK_TIMEOUT_MS` | `5000` | how long `tc3xx_eth_init()` waits for a link, checked every 10 ms; `0` does not wait |
| `TC3XX_ETH_DELAY_MS(ms)` | STM0 busy-wait | delay used during bring-up; an override must sleep at least `ms` milliseconds, so convert to ticks and round up |
| `TC3XX_ETH_RING_ATTR` | empty | attribute placing the rings, e.g. `__attribute__((section(".ethram")))` |
| `TC3XX_ETH_RX_IRQ` | `0` | `1` enables the receive interrupt |
| `TC3XX_ETH_RX_IRQ_PRIO` | none | its priority; required with `TC3XX_ETH_RX_IRQ` and unique on the servicing CPU |
| `TC3XX_ETH_RX_IRQ_TOS` | `IfxSrc_Tos_cpu0` | CPU servicing the interrupt |
| `TC3XX_ETH_RX_IRQ_VECTAB` | `0` | vector table of that CPU |

## Memory

The rings take about 24.8 KB: eight receive and eight transmit descriptors (fixed by the iLLD's `IFXGETH_MAX_*_DESCRIPTORS`) with a 1536-byte buffer each. The GETH DMA must reach them through a global address without a cache in between. The default, plain `.bss` in a CPU's DSPR, does that. If they move into LMU, use a non-cached segment.

## Receive interrupt

Without `TC3XX_ETH_RX_IRQ` the driver is purely polled. With it, the iLLD enables the DMA receive interrupt, and the handler clears it and calls the function passed to `tc3xx_eth_set_rx_notify()`, typically to wake the task that runs `wolfIP_poll()`. The callback runs in interrupt context and must not call wolfIP or the driver. The interrupt only shortens the wait: `wolfIP_poll()` handles a bounded number of frames per call and also runs wolfIP's timers, so the task must still wake periodically, not only on the callback. Otherwise frames left in the ring when that bound is reached wait until something else wakes it. The priority must be unique on the servicing CPU.

## Threading

The poll and send callbacks serialise their ring access by briefly disabling interrupts, so frames may be sent from a different task than the one polling. That only excludes code on the same CPU, so every driver entry point must run on one core. `tc3xx_eth_mdio_read()`, `tc3xx_eth_mdio_write()` and `tc3xx_eth_link_update()` are not serialised against each other and belong to a single context. As with every wolfIP port, only one context may call into the stack at a time.

## Limitations

- One GETH instance, one DMA channel per direction.
- RMII only, 10 and 100 Mbit/s.
- No checksum offload: wolfIP computes and verifies all checksums itself.
- Not built by CI, which has neither a TriCore compiler nor the iLLD.

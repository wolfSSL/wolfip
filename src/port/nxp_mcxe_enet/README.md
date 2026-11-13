# wolfIP NXP MCX E247 port

Ethernet driver for the NXP MCX E247: it programs the ENET MAC, the LAN8741 PHY (over MDIO) and, optionally, an eDMA channel. It can be polled or interrupt driven.

It is consumed by the wolfBoot test-app, which links wolfIP core, this driver and the TFTP client. See the NXP MCXE247 section of the wolfBoot `docs/Targets.md` for the build.

## Files

- `nxp_mcxe_enet.h` - public API, board parameters and build options.
- `nxp_mcxe_enet.c` - pin setup, PHY reset and link wait, MAC start, descriptor rings, wolfIP poll/send callbacks, interrupt handler.
- `nxp_mcxe_enet_regs.h` - the ENET, eDMA, clock-gate, pin, SCG, NVIC and DWT registers the driver uses (from the MCXE24x Reference Manual).
- `config.h` - wolfIP compile-time configuration for this port.

## Board

Defaults target the FRDM-MCXE247: RMII to a LAN8741A-EN PHY at MDIO address 0, 50 MHz RMII reference clock on PTD11 from the board oscillator, and PHY reset on PTC3.

| Define | Default | Notes |
|---|---|---|
| `NXP_MCXE_ENET_PHY_ADDR` | `0` | MDIO address of the PHY |
| `NXP_MCXE_ENET_MAC` | `{ 0x02, 0x00, 0xE2, 0x47, 0x00, 0x01 }` | used when `nxp_mcxe_enet_init()` is passed `mac=NULL` |
| `NXP_MCXE_ENET_SOSC_HZ` | `8000000` | system oscillator, used to work out the core clock when it runs from SOSC or the SPLL |

## Build options

| Define | Default | Notes |
|---|---|---|
| `NXP_MCXE_ENET_IRQ` | `0` | `1`: the receive interrupt marks frames waiting, so `poll()` returns at once when there are none, and `send()` sleeps in `wfi` until the transmit interrupt when the transmit ring is full. Route ENET IRQs 73 (transmit), 74 (receive) and 75 (error) to `nxp_mcxe_enet_irq_handler()`. |
| `NXP_MCXE_ENET_IRQ_PRIO` | `0x80` | NVIC priority of the ENET interrupts |
| `NXP_MCXE_ENET_EDMA` | `1` | copy frames between the descriptor rings and the wolfIP buffers with an eDMA channel instead of `memcpy`. The CPU waits for each copy. |
| `NXP_MCXE_ENET_EDMA_CH` | `0` | eDMA channel, reserved for the driver |
| `NXP_MCXE_ENET_EDMA_MIN` | `128` | shorter frames are copied with `memcpy` |
| `NXP_MCXE_ENET_STATS` | `0` | `1`: count frames and the core cycles (DWT) spent receiving, sending, polling an empty ring, copying and waiting for a free transmit descriptor; read with `nxp_mcxe_enet_stats_get()`. The wolfBoot test-app throughput test uses it for its CPU breakdown. |

## Data path

wolfIP hands the driver its own buffers: `poll()` must fill the buffer it is given, and `send()` must be done with the buffer when it returns.

- Receive: the MAC DMA writes each frame into one of 8 ring buffers (1536 bytes, one frame each). `poll()` copies it into the wolfIP buffer and returns the descriptor to the MAC.
- Transmit: `send()` copies each frame into one of 4 ring buffers, pads it to 60 bytes when short, and returns while the MAC sends it in the background. When all 4 are in use, `send()` waits for the oldest to go out.

## Memory

`config.h` defaults `RXBUF_SIZE` and `TXBUF_SIZE` to one `LINK_MTU`, which allows one TCP segment in flight. Each socket carries one buffer of each, so with the 5 sockets of this configuration every extra `LINK_MTU` on both costs 15 KB. The wolfBoot test-app sets both to 9216 (6 segments) and places the wolfIP state, 124.5 KB, in SRAM_L.

Descriptors and ring buffers, and every wolfIP buffer the MAC or the eDMA reads or writes, must be outside the code cache, e.g. in SRAM_U. The system MPU is disabled at init so that the ENET and eDMA bus masters can reach them.

An application that uses the ENET interrupts must place its vector table at a 1 KB aligned address.

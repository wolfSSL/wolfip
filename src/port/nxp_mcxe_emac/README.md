# wolfIP NXP MCX E EMAC port

Ethernet driver for the EMAC (Synopsys Ethernet QoS) of NXP MCX E parts: it programs the EMAC, its clock muxes, clock gate and pins, and the LAN8741 PHY (over MDIO). It can be polled or interrupt driven, and needs no vendor SDK. It was written for and tested on the MCX E31B; register addresses, clocks, pins and the IRQ number follow that part. Per the MCX E3 Reference Manual (MCXEP172M160FB0RM, Rev. 5), the EMAC is also in the MCX E327 and E32B (same base address and IRQ 105), and not in the E315, E316 or E317. The driver runs on Cortex-M7_0 and uses its DTCM; the second core of the E327 and E32B is not supported.

It is consumed by the wolfBoot test-app, which links wolfIP core, this driver and the TFTP client. See the NXP MCXE31B section of the wolfBoot `docs/Targets.md` for the build.

## Files

- `nxp_mcxe_emac.h` - public API, board parameters and build options.
- `nxp_mcxe_emac.c` - clocks, pins, PHY reset and link wait, MAC/MTL/DMA start, descriptor rings, wolfIP poll/send callbacks, interrupt handler.
- `nxp_mcxe_emac_regs.h` - the EMAC, MC_ME, MC_CGM, PLL, DCM_GPR, SIUL2, NVIC, SCB and DWT registers the driver uses (from the MCX E3 Reference Manual, MCXEP172M160FB0RM Rev. 5).
- `config.h` - wolfIP compile-time configuration for this port.

## Board

Defaults target the FRDM-MCXE31B: RMII to a LAN8741A-EN PHY at MDIO address 0, 50 MHz RMII reference clock on PTD11 from the board oscillator, and PHY reset on PTC3.

| Signal | Pad | Mux |
|---|---|---|
| MDIO | PTB4 | ALT5, IMCR 291 |
| MDC | PTB5 | ALT7 |
| TXD0, TXD1, TX_EN | PTC2, PTD7, PTD12 | ALT5 |
| RXD0, RXD1, RX_DV | PTC1, PTC0, PTC17 | input, IMCR 294, 295, 292 |
| REF_CLK (50 MHz in) | PTD11 | input, IMCR 296 |
| PHY reset | PTC3 | GPIO, active low |

The EMAC receive and transmit clocks (MC_CGM muxes 7 and 8) and the timestamp clock (mux 9) run from the reference clock pin, divided by 2 (25 MHz) at 100 Mbit/s and by 20 (2.5 MHz) at 10 Mbit/s. `DCM_GPR.DCMRWF1[MAC_CONF_SEL]` selects RMII before the EMAC is reset. The MDIO clock divider follows AIPS_PLAT_CLK, which the driver reads back from MC_CGM and the PLL.

| Define | Default | Notes |
|---|---|---|
| `NXP_MCXE_EMAC_PHY_ADDR` | `0` | MDIO address of the PHY |
| `NXP_MCXE_EMAC_MAC` | `{ 0x02, 0x00, 0xE3, 0x1B, 0x00, 0x01 }` | used when `nxp_mcxe_emac_init()` is passed `mac=NULL` |
| `NXP_MCXE_EMAC_FXOSC_HZ` | `16000000` | crystal, used to work out the core and bus clocks when they run from the PLL |

## Build options

| Define | Default | Notes |
|---|---|---|
| `NXP_MCXE_EMAC_IRQ` | `0` | `1`: the receive interrupt marks frames waiting, so `poll()` returns at once when there are none. Route EMAC IRQ 105 (the common line, which carries the DMA channel events) to `nxp_mcxe_emac_irq_handler()`. The transmit interrupt is not used. |
| `NXP_MCXE_EMAC_IRQ_PRIO` | `0x80` | NVIC priority of the EMAC interrupt |
| `NXP_MCXE_EMAC_RX_DESC` | `4` | receive descriptors, one 1536-byte buffer each. |
| `NXP_MCXE_EMAC_TX_DESC` | `8` | transmit descriptors, one 1536-byte buffer each. |
| `NXP_MCXE_EMAC_PBL` | `8` | DMA burst length in beats. |
| `NXP_MCXE_EMAC_SYSBUS` | `0x1001` | `DMA_SysBus_Mode`: fixed, address-aligned bursts (FB, AAL), slightly faster on transmit than the reset value 0 |
| `NXP_MCXE_EMAC_TX_OSF` | `1` | transmit DMA operates on the second frame. |
| `NXP_MCXE_EMAC_STATS` | `0` | `1`: count frames and the core cycles (DWT) spent receiving, sending, polling an empty ring, copying and waiting for a free transmit descriptor; read with `nxp_mcxe_emac_stats_get()`. The wolfBoot test-app throughput test uses it for its CPU breakdown. |

## Data path

wolfIP hands the driver its own buffers: `poll()` must fill the buffer it is given, and `send()` must be done with the buffer when it returns.

- Receive: the DMA writes each frame into one of the receive ring buffers (4 by default, 1536 bytes, one frame each, FCS stripped). `poll()` copies it into the wolfIP buffer and hands the descriptor back to the DMA. Frames with an error status are dropped in the same call, so that `poll()` returns 0 only when the ring is empty.
- Transmit: `send()` copies each frame into one of the transmit ring buffers (8 by default) and returns while the MAC sends it in the background; the MAC pads short frames and appends the FCS. When all are in use, `send()` polls until the oldest has gone out, for at most 5 ms.

## Memory

The descriptor rings and frame buffers (19 KB by default, the driver's `.bss`) must be in the CM7_0 DTCM. The core does not cache the DTCM, and the EMAC DMA reaches it through its backdoor port (`0x21000000`), so the driver does no cache maintenance. `nxp_mcxe_emac_init()` returns -5 when the D-cache is on and the buffers are elsewhere. The wolfIP buffers need no special placement: only the core reads and writes them.

`config.h` sets `LINK_MTU` to 1518, the largest frame the driver sends, so wolfIP rejects longer frames before it queues them. It defaults `RXBUF_SIZE` and `TXBUF_SIZE` to 1536 bytes, which allows one TCP segment in flight. The wolfBoot test-app sets both to 9216 (6 segments) and places the wolfIP state in SRAM.

An application that uses the EMAC interrupt must place its vector table at a 1 KB aligned address.

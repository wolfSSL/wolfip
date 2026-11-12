# wolfIP NXP MCX E247 port

Ethernet driver for the NXP MCX E247, built on the MCUXpresso SDK `fsl_enet` driver and `phylan8741` PHY component. It is polled, uses no interrupts, and drives one MAC.

It is consumed by the wolfBoot test-app, which links wolfIP core, this driver and the TFTP client. See the NXP MCXE247 section of the wolfBoot `docs/Targets.md` for the build.

## Files

- `nxp_mcxe_enet.h` - public API and board parameters.
- `nxp_mcxe_enet.c` - pin setup, PHY reset and link wait, MAC start, wolfIP poll/send callbacks.
- `config.h` - wolfIP compile-time configuration for this port.

## Board

Defaults target the FRDM-MCXE247: RMII to a LAN8741A-EN PHY at MDIO address 0, 50 MHz RMII reference clock on PTD11 from the board oscillator, and PHY reset on PTC3.

| Define | Default | Notes |
|---|---|---|
| `NXP_MCXE_ENET_PHY_ADDR` | `0` | MDIO address of the PHY |
| `NXP_MCXE_ENET_MAC` | `{ 0x02, 0x00, 0xE2, 0x47, 0x00, 0x01 }` | used when `nxp_mcxe_enet_init()` is passed `mac=NULL` |

## Memory

Buffer descriptors and frame buffers must be in SRAM_U, which is outside the code cache. The system MPU is disabled at init so that the ENET bus master can reach them.

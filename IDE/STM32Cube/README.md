# wolfIP for STM32 CubeIDE

This guide explains how to use wolfIP on any STM32 microcontroller with Ethernet using STM32CubeMX and the wolfIP CMSIS pack.

## Supported STM32 Families

| Family   | Interface Config | Auto-Detected | Example Boards |
|----------|------------------|---------------|----------------|
| STM32F4  | SYSCFG->PMC      | Yes           | NUCLEO-F429ZI, STM32F4-Discovery |
| STM32F7  | SYSCFG->PMC      | Yes           | NUCLEO-F746ZG, NUCLEO-F767ZI |
| STM32H5  | SBS->PMCR        | Yes           | NUCLEO-H563ZI, NUCLEO-H573ZI |
| STM32H7  | SYSCFG->PMCR     | Yes           | NUCLEO-H743ZI, NUCLEO-H753ZI |
| Others   | Manual           | Fallback      | See family reference manual |

## Quick Start

### Step 1: Install the wolfIP Pack

1. Download the pack from [wolfSSL](https://www.wolfssl.com/files/ide/I-CUBE-wolfIP.pack)
2. In STM32CubeMX: **Help → Manage Embedded Software Packages → From Local**
3. Select `I-CUBE-wolfIP.pack` and accept the license

### Step 2: Create CubeMX Project

1. Create new project for your board
2. Configure **Connectivity → ETH**:
   - Mode: **RMII** (or MII depending on board)
   - Verify GPIO pin assignments match your board's PHY (CubeMX auto-configures for NUCLEO boards)
3. Configure **System Core → NVIC**:
   - **ETH global interrupt: ENABLED** (CRITICAL - required for RX)
4. Configure **Software Packs → Select Components**:
   - Expand wolfIP → Check **Core** and **Eth**
5. Configure **Software Packs → wolfIP**:
   - Enable the library checkbox
6. Generate code (Makefile recommended for command-line builds)

**Note:** For NUCLEO boards, CubeMX auto-configures the correct ETH GPIO pins. For custom boards, verify pins match your PHY datasheet.

**That's it for CubeMX!** No MspInit changes needed - the driver auto-configures RMII/MII.

### Step 3: Add wolfIP Code to main.c

Add this code to your CubeMX-generated main.c in the corresponding USER CODE sections:

**In USER CODE BEGIN Includes:**
```c
#include "wolfip.h"
#include "stm32_hal_eth.h"
```

**In USER CODE BEGIN PV:**
```c
static struct wolfIP *ipstack = NULL;
```

**In USER CODE BEGIN 2 (after MX_ETH_Init):**
```c
wolfIP_init_static(&ipstack);
if (stm32_hal_eth_init(wolfIP_getdev(ipstack)) != 0) {
    Error_Handler();
}
wolfIP_ipconfig_set(ipstack,
    atoip4("192.168.0.200"),
    atoip4("255.255.255.0"),
    atoip4("192.168.0.1"));
```

**In USER CODE BEGIN 3 (inside while loop):**
```c
wolfIP_poll(ipstack, HAL_GetTick());
```

**In USER CODE BEGIN 4:**
```c
uint32_t wolfIP_getrandom(void)
{
    static uint32_t seed = 12345;
    seed = seed * 1103515245 + 12345;
    return (seed >> 16) ^ HAL_GetTick();
}
```

**Alternative: Use DHCP** instead of static IP by enabling DHCP in Software Packs -> wolfIP settings.

### Step 4: Build and Test

1. Build the project
2. Flash to your board
3. Connect Ethernet cable
4. Ping from your PC: `ping 192.168.0.200`

## Troubleshooting

### No ping response

1. **Check NVIC**: ETH global interrupt must be ENABLED in CubeMX
2. **Check cable**: Ensure Ethernet cable is connected and link LED is on
3. **Check IP**: Ensure IP address is on same subnet as your PC
4. **Check return value**: Verify `stm32_hal_eth_init()` returns 0

### stm32_hal_eth_init() returns -3

This means the ETH reinitialization failed. Check:
- ETH peripheral is properly configured in CubeMX
- GPIO pins are correctly assigned for your board's PHY

### Unsupported STM32 family

For families not auto-detected (F4, F7, H5, H7), add RMII/MII config in MspInit:

```c
void HAL_ETH_MspInit(ETH_HandleTypeDef* heth)
{
    if(heth->Instance==ETH)
    {
        /* USER CODE BEGIN ETH_MspInit 0 */
        /* Manual RMII config - see your STM32 family reference manual */
        __HAL_RCC_SYSCFG_CLK_ENABLE();
        SYSCFG->PMC |= SYSCFG_PMC_MII_RMII_SEL;  /* Example for F4/F7 */
        /* USER CODE END ETH_MspInit 0 */
        ...
    }
}
```

## Using TLS with wolfIP

To use TLS (HTTPS, secure sockets):

1. First install wolfSSL pack: [wolfSSL CubeIDE Guide](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md)
2. In Software Packs, also check **wolfSSL-IO** component
3. See wolfSSL examples for TLS socket usage

## Additional Resources

- [wolfIP GitHub](https://github.com/wolfSSL/wolfip)
- [STM32H563 Bare-metal Example](../../src/port/stm32h563/)
- [wolfSSL Support](mailto:support@wolfssl.com)

## Notes

- wolfIP uses zero dynamic memory allocation - all buffers are pre-allocated
- Default configuration supports 4 TCP sockets, 4 UDP sockets
- Adjust `config.h` for different socket pool sizes or buffer sizes

/* startup.c
 *
 * STM32H753ZI Cortex-M7 startup code
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#include <stdint.h>

/* Linker symbols */
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

/* Main entry point */
extern int main(void);

/* System initialization (clock setup) */
static void SystemInit(void);

void Reset_Handler(void)
{
    uint32_t *src, *dst;

    /* Enable FPU (CP10/CP11) - must be done before any FPU instruction.
     * Required because we compile with -mfloat-abi=hard and newlib's
     * printf uses FPU registers even for integer formatting. */
    *(volatile uint32_t *)0xE000ED88UL |= (0xFU << 20);
    __asm volatile ("dsb" ::: "memory");
    __asm volatile ("isb");

    /* Initialize system (clocks) */
    SystemInit();

    /* Copy .data section from Flash to RAM */
    src = &_sidata;
    dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }

    /* Zero-fill .bss section */
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }

    /* Call main */
    main();

    /* If main returns, loop forever */
    while (1) { }
}

/* STM32H753 RCC registers */
#define RCC_BASE            0x58024400UL
#define RCC_CR              (*(volatile uint32_t *)(RCC_BASE + 0x00))
#define RCC_CFGR            (*(volatile uint32_t *)(RCC_BASE + 0x10))
#define RCC_D1CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x18))
#define RCC_D2CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x1C))
#define RCC_D3CFGR          (*(volatile uint32_t *)(RCC_BASE + 0x20))
#define RCC_PLLCKSELR       (*(volatile uint32_t *)(RCC_BASE + 0x28))
#define RCC_PLLCFGR         (*(volatile uint32_t *)(RCC_BASE + 0x2C))
#define RCC_PLL1DIVR        (*(volatile uint32_t *)(RCC_BASE + 0x30))
#define RCC_PLL1FRACR       (*(volatile uint32_t *)(RCC_BASE + 0x34))
#define RCC_AHB4ENR         (*(volatile uint32_t *)(RCC_BASE + 0xE0))
#define RCC_APB4ENR         (*(volatile uint32_t *)(RCC_BASE + 0xF4))

/* Power control registers */
#define PWR_BASE            0x58024800UL
#define PWR_CR3             (*(volatile uint32_t *)(PWR_BASE + 0x0C))
#define PWR_D3CR            (*(volatile uint32_t *)(PWR_BASE + 0x18))

/* Flash registers */
#define FLASH_BASE          0x52002000UL
#define FLASH_ACR           (*(volatile uint32_t *)(FLASH_BASE + 0x00))

/* SCB registers for cache control */
#define SCB_CCR             (*(volatile uint32_t *)0xE000ED14)
#define SCB_ICIALLU         (*(volatile uint32_t *)0xE000EF50)
#define SCB_DCISW           (*(volatile uint32_t *)0xE000EF60)
#define SCB_CCSIDR          (*(volatile uint32_t *)0xE000ED80)
#define SCB_CSSELR          (*(volatile uint32_t *)0xE000ED84)

/* RCC_CR bits */
#define RCC_CR_HSION        (1U << 0)
#define RCC_CR_HSIRDY       (1U << 2)
#define RCC_CR_PLL1ON       (1U << 24)
#define RCC_CR_PLL1RDY      (1U << 25)

/* RCC_CFGR bits */
#define RCC_CFGR_SW_HSI     (0U << 0)
#define RCC_CFGR_SW_PLL1    (3U << 0)
#define RCC_CFGR_SWS_PLL1   (3U << 3)

static void SystemInit(void)
{
    uint32_t timeout;

    /* Enable HSI (64MHz internal oscillator) */
    RCC_CR |= RCC_CR_HSION;
    timeout = 100000;
    while (!(RCC_CR & RCC_CR_HSIRDY) && timeout > 0) {
        timeout--;
    }

    /* Configure Flash latency for high speed operation
     * At 64MHz HSI with VOS1, we need 1 wait state
     * FLASH_ACR: LATENCY = 1, WRHIGHFREQ = 1 */
    FLASH_ACR = (1U << 0) | (1U << 4);

    /* Use HSI directly (64MHz) for simplicity
     * This is sufficient for Ethernet and TLS operations
     *
     * For higher performance, PLL can be configured:
     * HSI (64MHz) / DIVM1 * DIVN1 / DIVP1 = sysclk
     * Example: 64 / 4 * 50 / 2 = 400MHz
     */

    /* Set domain prescalers for 64MHz operation:
     * D1CPRE = 1, D1PPRE = 1, HPRE = 1 */
    RCC_D1CFGR = 0;  /* No division */
    RCC_D2CFGR = 0;  /* APB1/APB2 = AHB/1 */
    RCC_D3CFGR = 0;  /* APB4 = AHB/1 */

    /* Enable SYSCFG clock for Ethernet RMII selection */
    RCC_APB4ENR |= (1U << 1);  /* SYSCFGEN */

    /* Small delay for clock stabilization */
    for (volatile int i = 0; i < 1000; i++) { }
}

/* Default handler for unused interrupts */
void Default_Handler(void)
{
    while (1) { }
}

/* Weak aliases for interrupt handlers */
void NMI_Handler(void)          __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void)    __attribute__((weak));
void MemManage_Handler(void)    __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)          __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)       __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)      __attribute__((weak, alias("Default_Handler")));

/* Hard fault handler with debug info */
void HardFault_Handler(void)
{
    /* Loop forever - can add debug output here */
    while (1) { }
}

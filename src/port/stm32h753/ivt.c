/* ivt.c
 *
 * STM32H753ZI Interrupt Vector Table
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 */
#include <stdint.h>

/* Linker-provided stack top */
extern uint32_t _estack;

/* Reset handler from startup.c */
extern void Reset_Handler(void);

/* Default handler - local definition for alias target */
static void default_handler(void)
{
    while (1) { }
}

/* Cortex-M7 exception handlers - weak aliases */
void NMI_Handler(void)        __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void)        __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void)   __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("default_handler")));

/* STM32H753 Interrupt handlers - declare weak aliases */
#define WEAK_ALIAS(name) void name(void) __attribute__((weak, alias("default_handler")))

WEAK_ALIAS(WWDG_IRQHandler);
WEAK_ALIAS(PVD_AVD_IRQHandler);
WEAK_ALIAS(TAMP_STAMP_IRQHandler);
WEAK_ALIAS(RTC_WKUP_IRQHandler);
WEAK_ALIAS(FLASH_IRQHandler);
WEAK_ALIAS(RCC_IRQHandler);
WEAK_ALIAS(EXTI0_IRQHandler);
WEAK_ALIAS(EXTI1_IRQHandler);
WEAK_ALIAS(EXTI2_IRQHandler);
WEAK_ALIAS(EXTI3_IRQHandler);
WEAK_ALIAS(EXTI4_IRQHandler);
WEAK_ALIAS(DMA1_Stream0_IRQHandler);
WEAK_ALIAS(DMA1_Stream1_IRQHandler);
WEAK_ALIAS(DMA1_Stream2_IRQHandler);
WEAK_ALIAS(DMA1_Stream3_IRQHandler);
WEAK_ALIAS(DMA1_Stream4_IRQHandler);
WEAK_ALIAS(DMA1_Stream5_IRQHandler);
WEAK_ALIAS(DMA1_Stream6_IRQHandler);
WEAK_ALIAS(ADC_IRQHandler);
WEAK_ALIAS(FDCAN1_IT0_IRQHandler);
WEAK_ALIAS(FDCAN2_IT0_IRQHandler);
WEAK_ALIAS(FDCAN1_IT1_IRQHandler);
WEAK_ALIAS(FDCAN2_IT1_IRQHandler);
WEAK_ALIAS(EXTI9_5_IRQHandler);
WEAK_ALIAS(TIM1_BRK_IRQHandler);
WEAK_ALIAS(TIM1_UP_IRQHandler);
WEAK_ALIAS(TIM1_TRG_COM_IRQHandler);
WEAK_ALIAS(TIM1_CC_IRQHandler);
WEAK_ALIAS(TIM2_IRQHandler);
WEAK_ALIAS(TIM3_IRQHandler);
WEAK_ALIAS(TIM4_IRQHandler);
WEAK_ALIAS(I2C1_EV_IRQHandler);
WEAK_ALIAS(I2C1_ER_IRQHandler);
WEAK_ALIAS(I2C2_EV_IRQHandler);
WEAK_ALIAS(I2C2_ER_IRQHandler);
WEAK_ALIAS(SPI1_IRQHandler);
WEAK_ALIAS(SPI2_IRQHandler);
WEAK_ALIAS(USART1_IRQHandler);
WEAK_ALIAS(USART2_IRQHandler);
WEAK_ALIAS(USART3_IRQHandler);
WEAK_ALIAS(EXTI15_10_IRQHandler);
WEAK_ALIAS(RTC_Alarm_IRQHandler);
WEAK_ALIAS(TIM8_BRK_TIM12_IRQHandler);
WEAK_ALIAS(TIM8_UP_TIM13_IRQHandler);
WEAK_ALIAS(TIM8_TRG_COM_TIM14_IRQHandler);
WEAK_ALIAS(TIM8_CC_IRQHandler);
WEAK_ALIAS(DMA1_Stream7_IRQHandler);
WEAK_ALIAS(FMC_IRQHandler);
WEAK_ALIAS(SDMMC1_IRQHandler);
WEAK_ALIAS(TIM5_IRQHandler);
WEAK_ALIAS(SPI3_IRQHandler);
WEAK_ALIAS(UART4_IRQHandler);
WEAK_ALIAS(UART5_IRQHandler);
WEAK_ALIAS(TIM6_DAC_IRQHandler);
WEAK_ALIAS(TIM7_IRQHandler);
WEAK_ALIAS(DMA2_Stream0_IRQHandler);
WEAK_ALIAS(DMA2_Stream1_IRQHandler);
WEAK_ALIAS(DMA2_Stream2_IRQHandler);
WEAK_ALIAS(DMA2_Stream3_IRQHandler);
WEAK_ALIAS(DMA2_Stream4_IRQHandler);
WEAK_ALIAS(ETH_IRQHandler);
WEAK_ALIAS(ETH_WKUP_IRQHandler);
WEAK_ALIAS(FDCAN_CAL_IRQHandler);
WEAK_ALIAS(DMA2_Stream5_IRQHandler);
WEAK_ALIAS(DMA2_Stream6_IRQHandler);
WEAK_ALIAS(DMA2_Stream7_IRQHandler);
WEAK_ALIAS(USART6_IRQHandler);
WEAK_ALIAS(I2C3_EV_IRQHandler);
WEAK_ALIAS(I2C3_ER_IRQHandler);
WEAK_ALIAS(OTG_HS_EP1_OUT_IRQHandler);
WEAK_ALIAS(OTG_HS_EP1_IN_IRQHandler);
WEAK_ALIAS(OTG_HS_WKUP_IRQHandler);
WEAK_ALIAS(OTG_HS_IRQHandler);
WEAK_ALIAS(DCMI_IRQHandler);
WEAK_ALIAS(CRYP_IRQHandler);
WEAK_ALIAS(HASH_RNG_IRQHandler);
WEAK_ALIAS(FPU_IRQHandler);
WEAK_ALIAS(UART7_IRQHandler);
WEAK_ALIAS(UART8_IRQHandler);
WEAK_ALIAS(SPI4_IRQHandler);
WEAK_ALIAS(SPI5_IRQHandler);
WEAK_ALIAS(SPI6_IRQHandler);
WEAK_ALIAS(SAI1_IRQHandler);
WEAK_ALIAS(LTDC_IRQHandler);
WEAK_ALIAS(LTDC_ER_IRQHandler);
WEAK_ALIAS(DMA2D_IRQHandler);
WEAK_ALIAS(SAI2_IRQHandler);
WEAK_ALIAS(QUADSPI_IRQHandler);
WEAK_ALIAS(LPTIM1_IRQHandler);
WEAK_ALIAS(CEC_IRQHandler);
WEAK_ALIAS(I2C4_EV_IRQHandler);
WEAK_ALIAS(I2C4_ER_IRQHandler);
WEAK_ALIAS(SPDIF_RX_IRQHandler);
WEAK_ALIAS(OTG_FS_EP1_OUT_IRQHandler);
WEAK_ALIAS(OTG_FS_EP1_IN_IRQHandler);
WEAK_ALIAS(OTG_FS_WKUP_IRQHandler);
WEAK_ALIAS(OTG_FS_IRQHandler);
WEAK_ALIAS(DMAMUX1_OVR_IRQHandler);
WEAK_ALIAS(HRTIM1_Master_IRQHandler);
WEAK_ALIAS(HRTIM1_TIMA_IRQHandler);
WEAK_ALIAS(HRTIM1_TIMB_IRQHandler);
WEAK_ALIAS(HRTIM1_TIMC_IRQHandler);
WEAK_ALIAS(HRTIM1_TIMD_IRQHandler);
WEAK_ALIAS(HRTIM1_TIME_IRQHandler);
WEAK_ALIAS(HRTIM1_FLT_IRQHandler);
WEAK_ALIAS(DFSDM1_FLT0_IRQHandler);
WEAK_ALIAS(DFSDM1_FLT1_IRQHandler);
WEAK_ALIAS(DFSDM1_FLT2_IRQHandler);
WEAK_ALIAS(DFSDM1_FLT3_IRQHandler);
WEAK_ALIAS(SAI3_IRQHandler);
WEAK_ALIAS(SWPMI1_IRQHandler);
WEAK_ALIAS(TIM15_IRQHandler);
WEAK_ALIAS(TIM16_IRQHandler);
WEAK_ALIAS(TIM17_IRQHandler);
WEAK_ALIAS(MDIOS_WKUP_IRQHandler);
WEAK_ALIAS(MDIOS_IRQHandler);
WEAK_ALIAS(JPEG_IRQHandler);
WEAK_ALIAS(MDMA_IRQHandler);
WEAK_ALIAS(SDMMC2_IRQHandler);
WEAK_ALIAS(HSEM1_IRQHandler);
WEAK_ALIAS(ADC3_IRQHandler);
WEAK_ALIAS(DMAMUX2_OVR_IRQHandler);
WEAK_ALIAS(BDMA_Channel0_IRQHandler);
WEAK_ALIAS(BDMA_Channel1_IRQHandler);
WEAK_ALIAS(BDMA_Channel2_IRQHandler);
WEAK_ALIAS(BDMA_Channel3_IRQHandler);
WEAK_ALIAS(BDMA_Channel4_IRQHandler);
WEAK_ALIAS(BDMA_Channel5_IRQHandler);
WEAK_ALIAS(BDMA_Channel6_IRQHandler);
WEAK_ALIAS(BDMA_Channel7_IRQHandler);
WEAK_ALIAS(COMP1_IRQHandler);
WEAK_ALIAS(LPTIM2_IRQHandler);
WEAK_ALIAS(LPTIM3_IRQHandler);
WEAK_ALIAS(LPTIM4_IRQHandler);
WEAK_ALIAS(LPTIM5_IRQHandler);
WEAK_ALIAS(LPUART1_IRQHandler);
WEAK_ALIAS(CRS_IRQHandler);
WEAK_ALIAS(ECC_IRQHandler);
WEAK_ALIAS(SAI4_IRQHandler);
WEAK_ALIAS(WAKEUP_PIN_IRQHandler);

/* Vector table - placed at start of flash */
__attribute__((section(".isr_vector")))
const void *g_pfnVectors[] = {
    &_estack,                       /* Initial stack pointer */
    Reset_Handler,                  /* Reset handler */
    NMI_Handler,                    /* NMI */
    HardFault_Handler,              /* Hard fault */
    MemManage_Handler,              /* MPU fault */
    BusFault_Handler,               /* Bus fault */
    UsageFault_Handler,             /* Usage fault */
    0, 0, 0, 0,                     /* Reserved */
    SVC_Handler,                    /* SVCall */
    DebugMon_Handler,               /* Debug monitor */
    0,                              /* Reserved */
    PendSV_Handler,                 /* PendSV */
    SysTick_Handler,                /* SysTick */

    /* STM32H753 External interrupts */
    WWDG_IRQHandler,                /* 0: Window Watchdog */
    PVD_AVD_IRQHandler,             /* 1: PVD/AVD through EXTI */
    TAMP_STAMP_IRQHandler,          /* 2: Tamper and TimeStamp */
    RTC_WKUP_IRQHandler,            /* 3: RTC Wakeup */
    FLASH_IRQHandler,               /* 4: Flash */
    RCC_IRQHandler,                 /* 5: RCC */
    EXTI0_IRQHandler,               /* 6: EXTI Line0 */
    EXTI1_IRQHandler,               /* 7: EXTI Line1 */
    EXTI2_IRQHandler,               /* 8: EXTI Line2 */
    EXTI3_IRQHandler,               /* 9: EXTI Line3 */
    EXTI4_IRQHandler,               /* 10: EXTI Line4 */
    DMA1_Stream0_IRQHandler,        /* 11: DMA1 Stream 0 */
    DMA1_Stream1_IRQHandler,        /* 12: DMA1 Stream 1 */
    DMA1_Stream2_IRQHandler,        /* 13: DMA1 Stream 2 */
    DMA1_Stream3_IRQHandler,        /* 14: DMA1 Stream 3 */
    DMA1_Stream4_IRQHandler,        /* 15: DMA1 Stream 4 */
    DMA1_Stream5_IRQHandler,        /* 16: DMA1 Stream 5 */
    DMA1_Stream6_IRQHandler,        /* 17: DMA1 Stream 6 */
    ADC_IRQHandler,                 /* 18: ADC1/ADC2 */
    FDCAN1_IT0_IRQHandler,          /* 19: FDCAN1 IT0 */
    FDCAN2_IT0_IRQHandler,          /* 20: FDCAN2 IT0 */
    FDCAN1_IT1_IRQHandler,          /* 21: FDCAN1 IT1 */
    FDCAN2_IT1_IRQHandler,          /* 22: FDCAN2 IT1 */
    EXTI9_5_IRQHandler,             /* 23: EXTI Lines 5-9 */
    TIM1_BRK_IRQHandler,            /* 24: TIM1 Break */
    TIM1_UP_IRQHandler,             /* 25: TIM1 Update */
    TIM1_TRG_COM_IRQHandler,        /* 26: TIM1 Trigger and Commutation */
    TIM1_CC_IRQHandler,             /* 27: TIM1 Capture Compare */
    TIM2_IRQHandler,                /* 28: TIM2 */
    TIM3_IRQHandler,                /* 29: TIM3 */
    TIM4_IRQHandler,                /* 30: TIM4 */
    I2C1_EV_IRQHandler,             /* 31: I2C1 Event */
    I2C1_ER_IRQHandler,             /* 32: I2C1 Error */
    I2C2_EV_IRQHandler,             /* 33: I2C2 Event */
    I2C2_ER_IRQHandler,             /* 34: I2C2 Error */
    SPI1_IRQHandler,                /* 35: SPI1 */
    SPI2_IRQHandler,                /* 36: SPI2 */
    USART1_IRQHandler,              /* 37: USART1 */
    USART2_IRQHandler,              /* 38: USART2 */
    USART3_IRQHandler,              /* 39: USART3 */
    EXTI15_10_IRQHandler,           /* 40: EXTI Lines 10-15 */
    RTC_Alarm_IRQHandler,           /* 41: RTC Alarm */
    0,                              /* 42: Reserved */
    TIM8_BRK_TIM12_IRQHandler,      /* 43: TIM8 Break and TIM12 */
    TIM8_UP_TIM13_IRQHandler,       /* 44: TIM8 Update and TIM13 */
    TIM8_TRG_COM_TIM14_IRQHandler,  /* 45: TIM8 Trigger/Commutation and TIM14 */
    TIM8_CC_IRQHandler,             /* 46: TIM8 Capture Compare */
    DMA1_Stream7_IRQHandler,        /* 47: DMA1 Stream7 */
    FMC_IRQHandler,                 /* 48: FMC */
    SDMMC1_IRQHandler,              /* 49: SDMMC1 */
    TIM5_IRQHandler,                /* 50: TIM5 */
    SPI3_IRQHandler,                /* 51: SPI3 */
    UART4_IRQHandler,               /* 52: UART4 */
    UART5_IRQHandler,               /* 53: UART5 */
    TIM6_DAC_IRQHandler,            /* 54: TIM6 and DAC1&2 underrun errors */
    TIM7_IRQHandler,                /* 55: TIM7 */
    DMA2_Stream0_IRQHandler,        /* 56: DMA2 Stream 0 */
    DMA2_Stream1_IRQHandler,        /* 57: DMA2 Stream 1 */
    DMA2_Stream2_IRQHandler,        /* 58: DMA2 Stream 2 */
    DMA2_Stream3_IRQHandler,        /* 59: DMA2 Stream 3 */
    DMA2_Stream4_IRQHandler,        /* 60: DMA2 Stream 4 */
    ETH_IRQHandler,                 /* 61: Ethernet */
    ETH_WKUP_IRQHandler,            /* 62: Ethernet Wakeup */
    FDCAN_CAL_IRQHandler,           /* 63: FDCAN calibration */
    0, 0, 0, 0,                     /* 64-67: Reserved */
    DMA2_Stream5_IRQHandler,        /* 68: DMA2 Stream 5 */
    DMA2_Stream6_IRQHandler,        /* 69: DMA2 Stream 6 */
    DMA2_Stream7_IRQHandler,        /* 70: DMA2 Stream 7 */
    USART6_IRQHandler,              /* 71: USART6 */
    I2C3_EV_IRQHandler,             /* 72: I2C3 event */
    I2C3_ER_IRQHandler,             /* 73: I2C3 error */
    OTG_HS_EP1_OUT_IRQHandler,      /* 74: USB OTG HS End Point 1 Out */
    OTG_HS_EP1_IN_IRQHandler,       /* 75: USB OTG HS End Point 1 In */
    OTG_HS_WKUP_IRQHandler,         /* 76: USB OTG HS Wakeup */
    OTG_HS_IRQHandler,              /* 77: USB OTG HS */
    DCMI_IRQHandler,                /* 78: DCMI */
    CRYP_IRQHandler,                /* 79: CRYP crypto */
    HASH_RNG_IRQHandler,            /* 80: Hash and Rng */
    FPU_IRQHandler,                 /* 81: FPU */
    UART7_IRQHandler,               /* 82: UART7 */
    UART8_IRQHandler,               /* 83: UART8 */
    SPI4_IRQHandler,                /* 84: SPI4 */
    SPI5_IRQHandler,                /* 85: SPI5 */
    SPI6_IRQHandler,                /* 86: SPI6 */
    SAI1_IRQHandler,                /* 87: SAI1 */
    LTDC_IRQHandler,                /* 88: LTDC */
    LTDC_ER_IRQHandler,             /* 89: LTDC error */
    DMA2D_IRQHandler,               /* 90: DMA2D */
    SAI2_IRQHandler,                /* 91: SAI2 */
    QUADSPI_IRQHandler,             /* 92: QUADSPI */
    LPTIM1_IRQHandler,              /* 93: LPTIM1 */
    CEC_IRQHandler,                 /* 94: HDMI_CEC */
    I2C4_EV_IRQHandler,             /* 95: I2C4 Event */
    I2C4_ER_IRQHandler,             /* 96: I2C4 Error */
    SPDIF_RX_IRQHandler,            /* 97: SPDIF_RX */
    OTG_FS_EP1_OUT_IRQHandler,      /* 98: USB OTG FS EP1 Out */
    OTG_FS_EP1_IN_IRQHandler,       /* 99: USB OTG FS EP1 In */
    OTG_FS_WKUP_IRQHandler,         /* 100: USB OTG FS Wakeup */
    OTG_FS_IRQHandler,              /* 101: USB OTG FS */
    DMAMUX1_OVR_IRQHandler,         /* 102: DMAMUX1 Overrun */
    HRTIM1_Master_IRQHandler,       /* 103: HRTIM Master Timer */
    HRTIM1_TIMA_IRQHandler,         /* 104: HRTIM Timer A */
    HRTIM1_TIMB_IRQHandler,         /* 105: HRTIM Timer B */
    HRTIM1_TIMC_IRQHandler,         /* 106: HRTIM Timer C */
    HRTIM1_TIMD_IRQHandler,         /* 107: HRTIM Timer D */
    HRTIM1_TIME_IRQHandler,         /* 108: HRTIM Timer E */
    HRTIM1_FLT_IRQHandler,          /* 109: HRTIM Fault */
    DFSDM1_FLT0_IRQHandler,         /* 110: DFSDM Filter0 */
    DFSDM1_FLT1_IRQHandler,         /* 111: DFSDM Filter1 */
    DFSDM1_FLT2_IRQHandler,         /* 112: DFSDM Filter2 */
    DFSDM1_FLT3_IRQHandler,         /* 113: DFSDM Filter3 */
    SAI3_IRQHandler,                /* 114: SAI3 */
    SWPMI1_IRQHandler,              /* 115: SWPMI1 */
    TIM15_IRQHandler,               /* 116: TIM15 */
    TIM16_IRQHandler,               /* 117: TIM16 */
    TIM17_IRQHandler,               /* 118: TIM17 */
    MDIOS_WKUP_IRQHandler,          /* 119: MDIOS Wakeup */
    MDIOS_IRQHandler,               /* 120: MDIOS */
    JPEG_IRQHandler,                /* 121: JPEG */
    MDMA_IRQHandler,                /* 122: MDMA */
    0,                              /* 123: Reserved */
    SDMMC2_IRQHandler,              /* 124: SDMMC2 */
    HSEM1_IRQHandler,               /* 125: HSEM1 */
    0,                              /* 126: Reserved */
    ADC3_IRQHandler,                /* 127: ADC3 */
    DMAMUX2_OVR_IRQHandler,         /* 128: DMAMUX2 Overrun */
    BDMA_Channel0_IRQHandler,       /* 129: BDMA Channel 0 */
    BDMA_Channel1_IRQHandler,       /* 130: BDMA Channel 1 */
    BDMA_Channel2_IRQHandler,       /* 131: BDMA Channel 2 */
    BDMA_Channel3_IRQHandler,       /* 132: BDMA Channel 3 */
    BDMA_Channel4_IRQHandler,       /* 133: BDMA Channel 4 */
    BDMA_Channel5_IRQHandler,       /* 134: BDMA Channel 5 */
    BDMA_Channel6_IRQHandler,       /* 135: BDMA Channel 6 */
    BDMA_Channel7_IRQHandler,       /* 136: BDMA Channel 7 */
    COMP1_IRQHandler,               /* 137: COMP1 */
    LPTIM2_IRQHandler,              /* 138: LPTIM2 */
    LPTIM3_IRQHandler,              /* 139: LPTIM3 */
    LPTIM4_IRQHandler,              /* 140: LPTIM4 */
    LPTIM5_IRQHandler,              /* 141: LPTIM5 */
    LPUART1_IRQHandler,             /* 142: LPUART1 */
    0,                              /* 143: Reserved */
    CRS_IRQHandler,                 /* 144: CRS */
    ECC_IRQHandler,                 /* 145: ECC */
    SAI4_IRQHandler,                /* 146: SAI4 */
    0,                              /* 147: Reserved */
    0,                              /* 148: Reserved */
    WAKEUP_PIN_IRQHandler,          /* 149: WAKEUP_PIN */
};

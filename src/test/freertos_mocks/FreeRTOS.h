#ifndef TEST_FREERTOS_H
#define TEST_FREERTOS_H

#include <stdint.h>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef uint32_t TickType_t;

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY ((TickType_t)0xffffffffu)
#ifndef configTICK_RATE_HZ
#define configTICK_RATE_HZ 1000u
#endif
#define portTICK_PERIOD_MS ((TickType_t)1000u / configTICK_RATE_HZ)
#define pdMS_TO_TICKS(ms) \
    ((TickType_t)(((uint64_t)(ms) * configTICK_RATE_HZ) / 1000u))
#define portYIELD_FROM_ISR(woken) ((void)(woken))

#endif

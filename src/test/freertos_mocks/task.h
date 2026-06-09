#ifndef TEST_TASK_H
#define TEST_TASK_H

#include "FreeRTOS.h"

typedef void (*TaskFunction_t)(void *);
typedef void * TaskHandle_t;

BaseType_t xTaskCreate(TaskFunction_t task, const char *name,
    uint16_t stack_words, void *arg, UBaseType_t priority, TaskHandle_t *handle);
void vTaskDelay(TickType_t ticks);
TickType_t xTaskGetTickCount(void);
void vTaskDelete(TaskHandle_t handle);

#endif

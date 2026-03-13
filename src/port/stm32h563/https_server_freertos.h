#ifndef HTTPS_SERVER_FREERTOS_H
#define HTTPS_SERVER_FREERTOS_H

#include <stdint.h>

struct wolfIP;

typedef void (*https_server_freertos_debug_cb)(const char *msg);

int https_server_freertos_start(struct wolfIP *stack, uint16_t port,
    https_server_freertos_debug_cb debug_cb);

#endif

#ifndef ECHO_SERVER_FREERTOS_H
#define ECHO_SERVER_FREERTOS_H

#include <stdint.h>

struct wolfIP;

typedef void (*echo_server_freertos_debug_cb)(const char *msg);

int echo_server_freertos_start(struct wolfIP *stack, uint16_t port,
    echo_server_freertos_debug_cb debug_cb);

#endif

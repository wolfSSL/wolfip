# wolfIP FreeRTOS Port

This directory provides a FreeRTOS integration layer for wolfIP with:

- A dedicated polling task that runs `wolfIP_poll()` in a loop.
- POSIX-style blocking socket calls (`socket`, `bind`, `listen`, `accept`, `recv`, `send`, `close`, ...).
- Event-driven wakeups from wolfIP callbacks, synchronized with FreeRTOS mutexes/semaphores.

## Files

- `bsd_socket.c`
  FreeRTOS socket wrapper implementation and poll task.
- `bsd_socket.h`
  Public API for initialization and socket calls.

## Design

1. A global lock protects wolfIP core/socket operations.
2. A poll thread/task calls `wolfIP_poll()` periodically.
3. Blocking socket operations:
   - Try the underlying non-blocking wolfIP socket call.
   - If `-WOLFIP_EAGAIN`, register a callback and block on a FreeRTOS semaphore.
   - Wake when the required event is observed, then retry.

This gives application code standard blocking socket behavior while wolfIP remains polled internally.

## Poll Task Example

The integration creates a dedicated task similar to:

```c
static void wolfip_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;

    for (;;) {
        uint32_t next_ms;
        TickType_t delay_ticks;
        uint64_t now_ms = (uint64_t)xTaskGetTickCount() * (uint64_t)portTICK_PERIOD_MS;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        next_ms = (uint32_t)wolfIP_poll(ipstack, now_ms);
        xSemaphoreGive(g_lock);

        if (next_ms < WOLFIP_FREERTOS_POLL_MIN_MS) {
            next_ms = WOLFIP_FREERTOS_POLL_MIN_MS;
        }
        if (next_ms > WOLFIP_FREERTOS_POLL_MAX_MS) {
            next_ms = WOLFIP_FREERTOS_POLL_MAX_MS;
        }

        delay_ticks = pdMS_TO_TICKS(next_ms);
        if (delay_ticks == 0) {
            delay_ticks = 1;
        }
        vTaskDelay(delay_ticks);
    }
}
```

## Integration Steps

1. Include headers:

```c
#include "wolfip.h"
#include "bsd_socket.h"
```

2. Initialize wolfIP core and low-level device first (your Ethernet/driver setup).
3. Start the FreeRTOS socket layer:

```c
int ret = wolfip_freertos_socket_init(ipstack, poll_task_priority, poll_task_stack_words);
```

4. Use POSIX-style socket API:

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
bind(fd, ...);
listen(fd, ...);
int cfd = accept(fd, NULL, NULL);
int n = recv(cfd, buf, sizeof(buf), 0);
send(cfd, buf, n, 0);
close(cfd);
close(fd);
```

## API

- `int wolfip_freertos_socket_init(struct wolfIP *ipstack, UBaseType_t poll_task_priority, uint16_t poll_task_stack_words);`
- `int socket_last_error(void);`
- Socket calls:
  - `socket`, `bind`, `listen`, `accept`, `connect`, `close`
  - `send`, `sendto`, `recv`, `recvfrom`
  - `setsockopt`, `getsockopt`, `getsockname`, `getpeername`

## Configuration Knobs

Defined in `bsd_socket.c`:

- `WOLFIP_FREERTOS_BSD_MAX_FDS` (default: `16`)
- `WOLFIP_FREERTOS_POLL_MIN_MS` (default: `5`)
- `WOLFIP_FREERTOS_POLL_MAX_MS` (default: `20`)

Override via compiler flags, for example:

```make
CFLAGS += -DWOLFIP_FREERTOS_BSD_MAX_FDS=32
```

## Notes

- `wolfip_freertos_socket_init()` should be called once after wolfIP/device init and before socket usage.
- File descriptors returned by this layer are wrapper FDs, not raw wolfIP internal FDs.
- The wrapper is intended for task context (not ISR context).

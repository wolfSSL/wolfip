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
2. A poll thread/task calls `wolfIP_poll()` and sleeps until the deadline it returns, bounded by `WOLFIP_FREERTOS_POLL_MIN_MS`/`WOLFIP_FREERTOS_POLL_MAX_MS`. The core wakes it early when a socket call queues work, and a link driver can wake it from its RX interrupt.
3. Blocking socket operations:
   - Try the underlying non-blocking wolfIP socket call.
   - If `-WOLFIP_EAGAIN`, register a callback and block on a FreeRTOS semaphore.
   - Wake when the required event is observed, then retry.

This gives application code standard blocking socket behavior while wolfIP remains polled internally.

## Poll Task Example

The integration registers a wake callback with `wolfIP_set_wake_cb()` that gives the binary semaphore `g_wake`, and creates a dedicated task similar to:

```c
static void wolfip_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;

    for (;;) {
        int next_ms;
        TickType_t delay_ticks;
        uint64_t now_ms = (uint64_t)xTaskGetTickCount() * 1000u / configTICK_RATE_HZ;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        next_ms = wolfIP_poll(ipstack, now_ms);
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
        (void)xSemaphoreTake(g_wake, delay_ticks);
    }
}
```

`WOLFIP_FREERTOS_POLL_MAX_MS` bounds how long a received frame waits when the link driver has no RX interrupt. `WOLFIP_FREERTOS_POLL_MIN_MS` keeps the task from spinning when `wolfIP_poll()` reports work still pending.

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
- `void wolfip_freertos_notify_from_isr(void);` - call from a link driver's receive interrupt so an arriving frame is serviced at once instead of after up to `WOLFIP_FREERTOS_POLL_MAX_MS`. Does nothing before `wolfip_freertos_socket_init()`. Only call it from interrupts at or below `configMAX_SYSCALL_INTERRUPT_PRIORITY`. Each call ends the poll task's sleep, so under sustained receive load it can starve lower-priority tasks; mask the RX interrupt in the ISR and re-enable it from `ll->poll` once the RX ring is drained.
- Socket calls:
  - `socket`, `bind`, `listen`, `accept`, `connect`, `close`
  - `send`, `sendto`, `recv`, `recvfrom`
  - `setsockopt`, `getsockopt`, `getsockname`, `getpeername`

## Configuration Knobs

Defined in `bsd_socket.c`:

- `WOLFIP_FREERTOS_BSD_MAX_FDS` (default: `16`)
- `WOLFIP_FREERTOS_POLL_MIN_MS` (default: `1`)
- `WOLFIP_FREERTOS_POLL_MAX_MS` (default: `5`)
- `WOLFIP_BSD_DEBUG_CALLBACK` (default: `0`) - set to `1` to log socket callbacks from the poll task

Override via compiler flags, for example:

```make
CFLAGS += -DWOLFIP_FREERTOS_BSD_MAX_FDS=32
```

## Notes

- `wolfip_freertos_socket_init()` should be called once after wolfIP/device init and before socket usage.
- File descriptors returned by this layer are wrapper FDs, not raw wolfIP internal FDs.
- The wrapper is intended for task context (not ISR context).
- Blocking calls wait indefinitely by default. `setsockopt(fd, WOLFIP_SOL_SOCKET, WOLFIP_SO_RCVTIMEO, &tv, sizeof(tv))` bounds `accept`, `recv` and `recvfrom`, and `WOLFIP_SO_SNDTIMEO` bounds `connect`, `send` and `sendto`, with `tv` a `struct wolfIP_timeval` and `optlen` exactly its size; each bounds the whole call, not each wait inside it. An expired wait returns -1 with `socket_last_error()` set to `WOLFIP_EAGAIN`; as on Linux, an all-zero `tv` or one too long for `TickType_t` waits without bound, a negative `tv_sec` does not wait, and a `tv_usec` outside [0, 999999] fails with `WOLFIP_EDOM`. A `connect()` that runs out of time fails with `WOLFIP_EINPROGRESS` instead, while the handshake goes on. `getsockopt()` reads the current values back.

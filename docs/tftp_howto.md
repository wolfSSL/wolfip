# TFTP How-To

This guide shows how to use the wolfIP **TFTP** module (`src/tftp/`): how to
build it, how to run a client (for example to pull a firmware image) and a
server, and how to wire its callback-driven, allocation-free core to wolfIP UDP
sockets.

It is a getting-started document. The authoritative API is `src/tftp/wolftftp.h`;
the worked examples come from `src/port/stm32h563/tftp_client_demo.c` (a
firmware-download client) and `src/test/test_tftp_interop.c` (a server tested
against Linux `tftp-hpa`).

## Table of Contents

- [1. What the TFTP module is](#1-what-the-tftp-module-is)
- [2. Building with TFTP](#2-building-with-tftp)
- [3. Architecture: callbacks, not blocking calls](#3-architecture-callbacks-not-blocking-calls)
- [4. The transport callback (UDP send)](#4-the-transport-callback-udp-send)
- [5. The I/O callbacks (storage)](#5-the-io-callbacks-storage)
- [6. Writing a client](#6-writing-a-client)
- [7. Writing a server](#7-writing-a-server)
- [8. Protocol options: blksize, timeout, windowsize, tsize](#8-protocol-options-blksize-timeout-windowsize-tsize)
- [9. Firmware download pattern (hash + verify)](#9-firmware-download-pattern-hash--verify)
- [10. Interop testing with tftp-hpa](#10-interop-testing-with-tftp-hpa)
- [11. Error codes and troubleshooting](#11-error-codes-and-troubleshooting)

---

## 1. What the TFTP module is

`src/tftp/` is a reusable, self-contained TFTP engine (RFC 1350 plus the option
extensions RFC 2347/2348/2349 and the windowsize extension RFC 7440). It
implements both a **client** and a **multi-session server**, and like the rest
of wolfIP it performs **zero dynamic allocation** — all state lives in
caller-provided `struct wolftftp_client` / `struct wolftftp_server` objects.

The module is deliberately decoupled from the socket layer. It never calls
`wolfIP_sock_*` itself; instead you give it:

- a **transport callback** that sends a UDP datagram, and
- a set of **I/O callbacks** that open/read/write/close your storage.

That makes the same engine usable over wolfIP, over POSIX sockets, or over any
other UDP transport. It also means the firmware-download path can stream bytes
straight into flash through your `write` callback, with an optional running hash
and a final verify step — no buffering of the whole image.

## 2. Building with TFTP

TFTP is opt-in. The default `config.h` sets `WOLFIP_ENABLE_TFTP 0`; enable it at
build time. With the top-level `Makefile`:

```sh
make WOLFIP_ENABLE_TFTP=1
```

This globs `src/tftp/*.c` into the shared library, static library, and
top-level executable, and defines `-DWOLFIP_ENABLE_TFTP=1`. The CMake build
globs `src/tftp/*.c` into the `wolfip` and `tcpip` targets with
`CONFIGURE_DEPENDS`, so no manual file list is needed there either.

Tunable compile-time limits (override in `config.h` or via `-D`), from
`wolftftp.h`:

| Macro | Default | Meaning |
|-------|---------|---------|
| `WOLFTFTP_PORT` | 69 | Well-known server port. |
| `WOLFTFTP_DEFAULT_BLKSIZE` | 512 | Block size before option negotiation. |
| `WOLFTFTP_MAX_BLKSIZE` | 1428 | Largest negotiable block (fits one Ethernet frame). |
| `WOLFTFTP_MAX_WINDOWSIZE` | 8 | Largest negotiable window (RFC 7440). |
| `WOLFTFTP_DEFAULT_TIMEOUT_S` | 1 | Per-block retransmit timeout. |
| `WOLFTFTP_MAX_RETRIES` | 5 | Retries before a transfer fails. |
| `WOLFTFTP_MAX_FILENAME` | 128 | Maximum request filename length. |
| `WOLFTFTP_SERVER_MAX_SESSIONS` | 4 | Concurrent server transfers. |
| `WOLFTFTP_SERVER_PORT_BASE` | 20000 | First ephemeral transfer port. |

## 3. Architecture: callbacks, not blocking calls

A TFTP transfer is driven by two engine entry points you call from your normal
poll loop, plus the callbacks the engine calls back into:

```text
                 your UDP socket
                  │          ▲
   recvfrom()     │          │  transport.send()  (you send the datagram)
                  ▼          │
   wolftftp_client_receive() │
                  │          │
            ┌─────┴──────────┴─────┐
            │   wolftftp engine    │── io.open/read/write/close ──▶ storage
            └─────────┬────────────┘── io.hash_update/verify ────▶ (optional)
                      │
   wolftftp_client_poll(now_ms)   (drives timeouts/retransmits)
```

The loop is always the same shape:

1. `recvfrom()` on your UDP socket; for each datagram call
   `wolftftp_*_receive(...)` to feed it to the engine.
2. Call `wolftftp_*_poll(now_ms)` once per loop iteration to service timeouts
   and retransmissions.
3. The engine calls your `transport.send` to put bytes on the wire and your
   `io.*` callbacks to touch storage.

Nothing blocks: `receive` and `poll` return immediately, so the TFTP engine
co-operates with the rest of `wolfIP_poll()` on a single thread.

## 4. The transport callback (UDP send)

The engine hands you a fully-formed TFTP datagram and a destination; you put it
on the wire. With wolfIP this is one `wolfIP_sock_sendto()`
(`src/port/stm32h563/tftp_client_demo.c`):

```c
static int demo_udp_send(void *arg, uint16_t local_port,
    const struct wolftftp_endpoint *remote, const uint8_t *buf, uint16_t len)
{
    struct wolfIP_sockaddr_in dst;
    int ret;

    (void)arg; (void)local_port;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = ee16(remote->port);          /* endpoint port is host order */
    dst.sin_addr.s_addr = ee32(remote->ip);     /* endpoint ip is host order   */
    ret = wolfIP_sock_sendto(g_stack, g_sock, buf, len, 0,
        (struct wolfIP_sockaddr *)&dst, sizeof(dst));
    return (ret == (int)len) ? 0 : (ret < 0 ? ret : -1);
}
```

Two conventions to note: `struct wolftftp_endpoint` carries `ip`/`port` in
**host byte order**, so convert with `ee32()`/`ee16()` when filling the wolfIP
sockaddr; and the callback returns `0` on success, a negative value on failure.

## 5. The I/O callbacks (storage)

`struct wolftftp_io_ops` decouples the protocol from where bytes live. You
implement the subset your role needs (a download client needs `write`; a server
serving files needs `read`; both need `open`/`close`):

```c
struct wolftftp_io_ops {
    wolftftp_open_cb  open;        /* open(name, is_write, *size_hint, **handle) */
    wolftftp_read_cb  read;        /* server -> client: produce file bytes       */
    wolftftp_write_cb write;       /* client <- server: consume file bytes       */
    wolftftp_hash_update_cb hash_update;  /* optional: running hash of payload   */
    wolftftp_verify_cb verify;     /* optional: final integrity/size check       */
    wolftftp_close_cb close;       /* finalize, status = 0 ok or WOLFTFTP_ERR_*  */
    void *arg;                     /* opaque context passed to every callback     */
};
```

A filesystem-backed server `open`/`read` (`src/test/test_tftp_interop.c`):

```c
static int io_open(void *arg, const char *name, int is_write,
    uint32_t *size_hint, void **handle)
{
    struct tftp_file_ctx *ctx = (struct tftp_file_ctx *)arg;
    struct stat st;

    ctx->fp = fopen(ctx->path, is_write ? "wb+" : "rb");
    if (ctx->fp == NULL) return -1;
    if (!is_write && stat(ctx->path, &st) == 0 && size_hint != NULL)
        *size_hint = (uint32_t)st.st_size;     /* advertised as tsize */
    *handle = ctx->fp;
    return 0;
}

static int io_read(void *arg, void *handle, uint32_t offset,
    uint8_t *buf, uint16_t max_len, uint16_t *out_len, int *is_last)
{
    FILE *fp = (FILE *)handle;
    if (fseek(fp, (long)offset, SEEK_SET) != 0) return -1;
    *out_len = (uint16_t)fread(buf, 1, max_len, fp);
    /* Flag EOF only on a short read; a file ending on a block boundary needs
     * one more 0-byte DATA block (RFC 1350), so a full read is NOT the last. */
    *is_last = (*out_len < max_len) ? 1 : 0;
    return 0;
}
```

`read` is **offset-addressed**: the engine tells you where to read from, which
is what lets it replay a window on a retransmit without you tracking position.
The `is_last` out-param and the trailing zero-byte block are the classic TFTP
EOF subtlety — see the header comment on `wolftftp_read_cb`.

> **Security note.** The server rejects absolute paths and any `..` component
> before calling `open`, but `name` may still contain relative subdirectories.
> Resolve it against a confined root (chroot or a fixed base directory), not the
> process cwd.

## 6. Writing a client

A client transfer is: create and bind a UDP socket, fill the three config
structs, `wolftftp_client_init()`, then `wolftftp_client_start_rrq()` to kick off
a read request. Condensed from `tftp_client_demo.c`:

```c
struct wolftftp_client      g_client;
struct wolftftp_transport_ops tx = {0};
struct wolftftp_io_ops        io = {0};
struct wolftftp_transfer_cfg  cfg = {0};
struct wolftftp_endpoint      server_ep;

/* 1. UDP socket bound to a fixed local port */
g_sock = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_DGRAM, 0);
/* bind g_sock to TFTP_CLIENT_LOCAL_PORT ... */

/* 2. transport + storage callbacks */
tx.send  = demo_udp_send;
io.open  = demo_open;
io.write = demo_write;          /* download: bytes go to flash */
io.close = demo_close;

/* 3. transfer parameters (0 leaves a field at its built-in default) */
cfg.local_port  = TFTP_CLIENT_LOCAL_PORT;
cfg.blksize     = TFTP_DEMO_BLKSIZE;
cfg.timeout_s   = TFTP_DEMO_TIMEOUT_S;
cfg.windowsize  = TFTP_DEMO_WINDOWSIZE;
cfg.max_retries = TFTP_DEMO_MAX_RETRIES;
cfg.max_image_size = WOLFBOOT_PARTITION_SIZE;   /* hard cap, refuses bigger */

/* 4. initialise and start the read request */
wolftftp_client_init(&g_client, &tx, &io, &cfg);
server_ep.ip = server_ip;            /* host byte order */
server_ep.port = WOLFTFTP_PORT;      /* 69 */
wolftftp_client_start_rrq(&g_client, &server_ep, filename);
```

Then drive it from your poll loop — pump received datagrams into the engine and
call `poll` for timers:

```c
void tftp_client_demo_poll(uint32_t now_ms)
{
    struct wolfIP_sockaddr_in remote;
    socklen_t rlen = sizeof(remote);
    int n;

    for (;;) {
        n = wolfIP_sock_recvfrom(g_stack, g_sock, g_rx_buf, sizeof(g_rx_buf),
                0, (struct wolfIP_sockaddr *)&remote, &rlen);
        if (n <= 0) break;
        struct wolftftp_endpoint rep = {
            .ip   = ee32(remote.sin_addr.s_addr),   /* back to host order */
            .port = ee16(remote.sin_port)
        };
        wolftftp_client_receive(&g_client, TFTP_CLIENT_LOCAL_PORT, &rep,
                                g_rx_buf, (uint16_t)n);
    }
    wolftftp_client_poll(&g_client, now_ms);
}
```

Poll the result with `wolftftp_client_status()`: a positive value means "in
progress," `0` means success, and a negative value is a `WOLFTFTP_ERR_*` code.

## 7. Writing a server

The server is the same pattern with two sockets: a **listen** socket on port 69
for incoming RRQ/WRQ, and one or more **transfer** sockets on ephemeral ports
(each active session gets its own TID). You feed datagrams from both into
`wolftftp_server_receive()`, tagging each with the local port it arrived on so
the engine can route it to the right session. From
`src/test/test_tftp_interop.c`:

```c
struct wolftftp_server server;
struct wolftftp_transport_ops transport = {0};
struct wolftftp_io_ops        io = {0};
struct wolftftp_transfer_cfg  cfg = {0};

transport.send = server_send;
io.open  = io_open;
io.read  = io_read;            /* serve file bytes */
io.write = io_write;           /* accept uploads   */
io.close = server_io_close;
io.arg   = &file_ctx;

cfg.blksize = WOLFTFTP_DEFAULT_BLKSIZE;
cfg.timeout_s = 2;
cfg.windowsize = 1;
cfg.max_retries = 5;

wolftftp_server_init(&server, &transport, &io, &cfg);
server.listen_port        = TFTP_INTEROP_PORT;          /* 69 in production */
server.transfer_port_base = TFTP_INTEROP_TRANSFER_PORT;  /* ephemeral base   */
```

Poll loop — drain both sockets, route by local port, then service timers:

```c
int socks[2] = { listen_sock, transfer_sock };
uint16_t ports[2] = { TFTP_INTEROP_PORT, TFTP_INTEROP_TRANSFER_PORT };

wolfIP_poll(s, now_ms());
for (int i = 0; i < 2; i++) {
    for (;;) {
        int n = wolfIP_sock_recvfrom(s, socks[i], pkt, sizeof(pkt), 0,
                    (struct wolfIP_sockaddr *)&remote, &rlen);
        if (n <= 0) break;
        struct wolftftp_endpoint rep = {
            .ip = ee32(remote.sin_addr.s_addr), .port = ee16(remote.sin_port) };
        wolftftp_server_receive(&server, ports[i], &rep, pkt, (uint16_t)n);
    }
}
wolftftp_server_poll(&server, (uint32_t)now_ms());
```

Concurrency is bounded by `WOLFTFTP_SERVER_MAX_SESSIONS`; a new request that
finds no free session slot is rejected with a TFTP error rather than queued.

## 8. Protocol options: blksize, timeout, windowsize, tsize

The engine implements the TFTP option extensions and negotiates them in the
RRQ/WRQ → OACK exchange:

- **blksize (RFC 2348)** — larger blocks mean fewer round trips. Set
  `cfg.blksize` up to `WOLFTFTP_MAX_BLKSIZE` (1428, sized to fit one Ethernet
  frame without IP fragmentation).
- **timeout (RFC 2349)** — `cfg.timeout_s` is the per-block retransmit timeout.
- **windowsize (RFC 7440)** — `cfg.windowsize > 1` lets the sender stream
  several DATA blocks before waiting for an ACK, which dramatically improves
  throughput on links with latency. Capped at `WOLFTFTP_MAX_WINDOWSIZE`.
- **tsize (RFC 2349)** — the transfer size. A server advertises it from the
  `size_hint` your `open` returns; a download client can compare the final byte
  count against the advertised `tsize` in its `verify` step.

The negotiated values land in `struct wolftftp_negotiated` inside the
client/server object. Set a `cfg` field to `0` to keep the built-in default for
that option.

## 9. Firmware download pattern (hash + verify)

The reason the I/O layer exposes `hash_update` and `verify` is firmware
delivery: stream each DATA block straight into flash, fold it into a running
hash as it arrives, and validate the whole image at the end — without ever
holding the full image in RAM. The flow:

1. `open(is_write=1)` — unlock/erase the target flash partition, stash a handle.
2. `write(offset, buf, len)` — program bytes at `offset` into flash.
3. `hash_update(buf, len)` — feed the same bytes to a streaming hash (optional).
4. `verify(total_size)` — compare `total_size` against the advertised `tsize`,
   finalize the hash / signature check, and set the boot-update flag.
5. `close(status)` — lock flash; `status == 0` means the transfer succeeded.

`cfg.max_image_size` is a hard ceiling: the engine refuses a transfer whose
advertised or actual size would exceed it, protecting a fixed flash partition.
See `tftp_client_demo.c` for a complete STM32H5 + wolfBoot implementation,
including erase-on-demand and trailer programming.

## 10. Interop testing with tftp-hpa

The repository ships an interop harness that runs the wolfIP server against the
standard Linux `tftp-hpa` client (`src/test/test_tftp_interop.c`, configured by
`tools/scripts/tftpd-hpa-wolfip.conf`). The Linux client is driven with
`tftp <ip> -c get <file>`, issuing an RRQ that the wolfIP server answers,
serving the fixture file through `io_read`. This is the recommended way to
validate option negotiation (blksize/windowsize/tsize) against a reference
implementation when you change the engine.

## 11. Error codes and troubleshooting

Negative return values and `close`/`verify` statuses use the `WOLFTFTP_ERR_*`
codes from `wolftftp.h`:

| Code | Meaning |
|------|---------|
| `WOLFTFTP_ERR_IO` (-1000) | An `io.*` callback failed (open/read/write/flash). |
| `WOLFTFTP_ERR_STATE` (-1001) | Operation invalid for the current transfer state. |
| `WOLFTFTP_ERR_PACKET` (-1002) | Malformed TFTP packet. |
| `WOLFTFTP_ERR_TIMEOUT` (-1003) | Retries exhausted with no progress. |
| `WOLFTFTP_ERR_SIZE` (-1004) | Transfer exceeds `cfg.max_image_size`. |
| `WOLFTFTP_ERR_VERIFY` (-1005) | Final `verify` callback rejected the image. |
| `WOLFTFTP_ERR_UNSUPPORTED` (-1006) | Unsupported request/option. |
| `WOLFTFTP_ERR_TID` (-1007) | Datagram from an unexpected transfer ID/port. |
| `WOLFTFTP_ERR_NO_SLOT` (-1008) | Server session pool full. |

Common issues:

- **Transfer stalls / times out.** You are probably not calling
  `wolftftp_*_poll(now_ms)` every loop iteration, or `now_ms` is not advancing —
  the engine needs a monotonic millisecond clock to drive retransmits.
- **Bytes never reach storage.** The `write` callback returned non-zero, or the
  client wired `io.read` instead of `io.write` (download = `write`).
- **`WOLFTFTP_ERR_TID`.** A reply arrived on the wrong port. Make sure you pass
  the correct `local_port` to `*_receive()` for the socket the datagram came in
  on, and that the transfer socket is bound.
- **Endianness garbage in addresses.** `struct wolftftp_endpoint` is host byte
  order; convert with `ee16()`/`ee32()` at the wolfIP sockaddr boundary.
- **Server rejects a new transfer.** All `WOLFTFTP_SERVER_MAX_SESSIONS` slots
  are busy; raise the limit or shorten transfers.

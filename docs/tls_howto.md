# TLS (wolfSSL) How-To

This guide shows how to run **TLS with wolfSSL on top of wolfIP sockets**: how to
build wolfIP with the wolfSSL glue, how the I/O-callback bridge lets wolfSSL read
and write through a wolfIP socket, and how to drive non-blocking client and
server handshakes from the `wolfIP_poll()` loop.

It is a getting-started document, not a reference manual. The authoritative glue
is `src/port/wolfssl_io.c` (declared in `wolfip.h` under `WOLFSSL_WOLFIP`); the
worked examples come from `src/test/test_native_wolfssl.c` (a wolfIP TLS echo
server tested against a Linux wolfSSL client) and the bare-metal demos
`src/port/stm32h563/tls_client.c` and `src/port/stm32h563/tls_server.c`. The
wolfSSL TLS API itself (`wolfSSL_CTX_new`, `wolfSSL_connect`, `wolfSSL_read`, …)
is documented by wolfSSL; this guide only covers the wolfIP integration points.

## Table of Contents

- [1. What the integration provides](#1-what-the-integration-provides)
- [2. Building with wolfSSL support](#2-building-with-wolfssl-support)
- [3. The I/O callback bridge](#3-the-io-callback-bridge)
- [4. Data path: TLS over a wolfIP socket](#4-data-path-tls-over-a-wolfip-socket)
- [5. The wolfIP glue API](#5-the-wolfip-glue-api)
- [6. Setting up a TLS client](#6-setting-up-a-tls-client)
- [7. Setting up a TLS server](#7-setting-up-a-tls-server)
- [8. Non-blocking handshakes and the poll loop](#8-non-blocking-handshakes-and-the-poll-loop)
- [9. Cleanup and the static descriptor pool](#9-cleanup-and-the-static-descriptor-pool)
- [10. Troubleshooting](#10-troubleshooting)

---

## 1. What the integration provides

wolfSSL speaks TLS over an abstract byte transport: it never touches the network
directly, but instead calls a pair of application-supplied **I/O callbacks** to
move ciphertext on and off the wire. The wolfIP integration supplies that pair,
bound to a wolfIP TCP socket. The result is plain TLS (any version your wolfSSL
build supports — the examples use TLS 1.3) running on top of `wolfIP_sock_*`
streams, with no extra abstraction layer.

For applications migrating from lwIP's ALTCP-over-TLS, this is the wolfIP-side
replacement point: instead of an `altcp` allocator that wraps TLS under a PCB,
you open an ordinary wolfIP socket and attach a `WOLFSSL` object to it. See
`docs/migrating_from_lwIP.md` §9 for the lwIP-to-wolfIP mapping; this document
goes deeper on the concrete wiring.

What the glue does:

- Registers wolfIP send/recv callbacks on a `WOLFSSL_CTX` so every `WOLFSSL`
  object created from that context reads and writes through wolfIP.
- Binds an individual `WOLFSSL` session to a specific wolfIP socket fd.
- Translates wolfIP's non-blocking `-WOLFIP_EAGAIN` into wolfSSL's
  `WANT_READ`/`WANT_WRITE`, and treats every other failure as a fatal close.

What it does **not** do: it does not manage certificates, sockets, or the TLS
state machine for you. You still create the `WOLFSSL_CTX`, load certs/keys, open
and connect/accept the wolfIP socket, and drive the handshake. The glue is only
the transport bridge.

## 2. Building with wolfSSL support

The integration is gated by the **`WOLFSSL_WOLFIP`** macro and lives in one
source file, `src/port/wolfssl_io.c`, which you compile in and link against
`-lwolfssl`.

With the top-level `Makefile`, the wolfSSL test targets already define the flag
and link the glue. For example the wolfIP TLS echo-server test (`Makefile`):

```make
build/test-wolfssl: CFLAGS += -Wno-cpp -DWOLFSSL_DEBUG -DWOLFSSL_WOLFIP
build/test-wolfssl: $(OBJ) build/test/test_native_wolfssl.o build/port/wolfssl_io.o \
                    build/certs/server_key.o build/certs/ca_cert.o build/certs/server_cert.o
	$(CC) $(CFLAGS) -o $@ ... -lwolfssl ...
```

The CMake build mirrors this (`CMakeLists.txt`): it `find_package(wolfssl)`,
compiles `src/port/wolfssl_io.c` into the target, sets
`-DWOLFSSL_WOLFIP`, and `target_link_libraries(... wolfssl)`.

To add TLS to your own build:

1. Build and install wolfSSL first (the examples use a TLS 1.3 configuration).
2. Compile `src/port/wolfssl_io.c` together with your application.
3. Add `-DWOLFSSL_WOLFIP` to the wolfIP/application `CFLAGS` so the declarations
   in `wolfip.h` are exposed.
4. Link with `-lwolfssl`.

When `WOLFSSL_WOLFIP` is defined, `wolfip.h` pulls in the wolfSSL headers and
declares the three glue functions (`wolfip.h`):

```c
#ifdef WOLFSSL_WOLFIP
    ...
    #include <wolfssl/ssl.h>
    int  wolfSSL_SetIO_wolfIP(WOLFSSL* ssl, int fd);
    int  wolfSSL_SetIO_wolfIP_CTX(WOLFSSL_CTX *ctx, struct wolfIP *s);
    void wolfSSL_CleanupIO_wolfIP(WOLFSSL* ssl);
#endif /* WOLFSSL_WOLFIP */
```

One compile-time knob, `MAX_WOLFIP_CTX` (default 8, in `src/port/wolfssl_io.c`),
sizes the static pools used internally — see §9.

## 3. The I/O callback bridge

wolfSSL calls a *receive* callback when it needs more ciphertext and a *send*
callback when it has ciphertext to emit. The glue implements both as thin
wrappers over `wolfIP_sock_recv()` / `wolfIP_sock_send()`
(`src/port/wolfssl_io.c`):

```c
static int wolfIP_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    struct wolfip_io_desc *desc = (struct wolfip_io_desc *)ctx;
    int ret;
    (void)ssl;

    if (!desc || !desc->stack)
        return WOLFSSL_CBIO_ERR_GENERAL;

    ret = wolfIP_sock_recv(desc->stack, desc->fd, buf, sz, 0);
    /* Only -WOLFIP_EAGAIN means "would block" ... A -1 is the "not
     * established" / torn-down case and must be reported as a fatal close. */
    if (ret == -WOLFIP_EAGAIN)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    if (ret <= 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}
```

The send callback is symmetric: `-WOLFIP_EAGAIN` (TX buffer full, nothing
queued) maps to `WOLFSSL_CBIO_ERR_WANT_WRITE`, any other non-positive return
maps to `WOLFSSL_CBIO_ERR_CONN_CLOSE`, and a positive return is the byte count.

The `ctx` argument is a `struct wolfip_io_desc { int fd; struct wolfIP *stack; }`
— the per-session binding of a wolfSSL object to one wolfIP socket on one stack.
This is the crux of the non-blocking model: **the glue never blocks.** When the
socket has no data (or no TX room), it returns `WANT_READ`/`WANT_WRITE` so
wolfSSL unwinds, and you re-drive it on the next poll iteration (§8).

The error mapping is deliberate. `-WOLFIP_EAGAIN` is the *only* "try again
later" signal; any other negative or zero return is the connection being gone,
and is reported as a hard close so wolfSSL does not spin forever retrying a dead
socket and leaking its session.

## 4. Data path: TLS over a wolfIP socket

```text
  app: wolfSSL_write(ssl, plaintext)
        │  (TLS record layer encrypts)
        ▼
  wolfIP_io_send ──▶ wolfIP_sock_send(stack, fd, ciphertext)
        │                                    │
        │  -WOLFIP_EAGAIN ─▶ WANT_WRITE      ▼  (queued; flushed by wolfIP_poll)
        ▲                               TCP / IP / Ethernet ──▶ wire
        │
  app: wolfSSL_read(ssl, plaintext)
        │  (TLS record layer decrypts)
        ▼
  wolfIP_io_recv ◀── wolfIP_sock_recv(stack, fd, ciphertext)
        │                                    ▲
        │  -WOLFIP_EAGAIN ─▶ WANT_READ       │
                                        wire ──▶ Ethernet / IP / TCP
```

The application sees plaintext via `wolfSSL_read`/`wolfSSL_write`; wolfIP sees
ciphertext via ordinary `wolfIP_sock_recv`/`wolfIP_sock_send`. Actual transmit
and receive progress on the socket happens inside `wolfIP_poll()`, exactly as
for a non-TLS socket — TLS adds the record layer on top but changes nothing
about how the byte stream is pumped.

## 5. The wolfIP glue API

Three functions, all in `src/port/wolfssl_io.c`:

| Function | When to call | Effect |
|----------|--------------|--------|
| `wolfSSL_SetIO_wolfIP_CTX(ctx, stack)` | once, after `wolfSSL_CTX_new`, before any `wolfSSL_new` | Installs the wolfIP send/recv callbacks on the CTX and records which `struct wolfIP *` stack this CTX uses. |
| `wolfSSL_SetIO_wolfIP(ssl, fd)` | once per session, after `wolfSSL_new`, before the handshake | Binds this `WOLFSSL` object to wolfIP socket `fd` (resolving the stack from the CTX) by setting its read/write I/O contexts. |
| `wolfSSL_CleanupIO_wolfIP(ssl)` | on every teardown path, before `wolfSSL_free` | Releases the static descriptor slot allocated by `wolfSSL_SetIO_wolfIP()`. |

Return values: `wolfSSL_SetIO_wolfIP_CTX` returns `0`. `wolfSSL_SetIO_wolfIP`
returns `0` on success and `-1` on a bad argument or an exhausted descriptor pool
(it returns `WOLFSSL_CBIO_ERR_GENERAL` if the CTX has no registered stack — i.e.
you forgot the `_CTX` call). Always check it for `0`.

The order matters and is the same for client and server:

```c
wolfSSL_SetIO_wolfIP_CTX(ctx, stack);   /* once per CTX  */
...
ssl = wolfSSL_new(ctx);
wolfSSL_SetIO_wolfIP(ssl, sockfd);      /* once per WOLFSSL session */
```

`wolfSSL_SetIO_wolfIP_CTX` must precede `wolfSSL_SetIO_wolfIP`, because the
per-session call looks up the stack that was registered against the CTX.

## 6. Setting up a TLS client

A client is: create a TLS-client `WOLFSSL_CTX`, configure verification and CAs,
register the wolfIP callbacks on the CTX, open and connect a wolfIP TCP socket,
then per connection create a `WOLFSSL` object, bind it to the fd, and drive
`wolfSSL_connect()` to completion. Condensed from
`src/port/stm32h563/tls_client.c`:

```c
/* 1. Library + client context (TLS 1.3) */
wolfSSL_Init();
client.ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());

/* 2. Verification policy. The demo disables it for testing; in production
 *    load a CA and keep verification on. */
wolfSSL_CTX_set_verify(client.ctx, WOLFSSL_VERIFY_NONE, NULL);
/* production: wolfSSL_CTX_load_verify_buffer(ctx, ca_der, ca_der_len,
 *             SSL_FILETYPE_ASN1); and WOLFSSL_VERIFY_PEER */

/* 3. Register the wolfIP I/O callbacks on the CTX */
wolfSSL_SetIO_wolfIP_CTX(client.ctx, stack);
```

Then per connection, open and connect a non-blocking wolfIP socket
(`tls_client.c`):

```c
client.fd = wolfIP_sock_socket(client.stack, AF_INET, IPSTACK_SOCK_STREAM, 0);

memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_port = ee16(port);
addr.sin_addr.s_addr = ee32(client.server_ip);

ret = wolfIP_sock_connect(client.stack, client.fd,
                          (struct wolfIP_sockaddr *)&addr, sizeof(addr));
/* -WOLFIP_EAGAIN means the connect is in progress: keep polling */
```

Once the TCP connection is established, create the session, optionally set SNI,
bind it to the socket, and run the handshake (`tls_client.c`):

```c
client.ssl = wolfSSL_new(client.ctx);

/* Server Name Indication, required by most public servers */
wolfSSL_UseSNI(client.ssl, WOLFSSL_SNI_HOST_NAME, host, host_len);

ret = wolfSSL_SetIO_wolfIP(client.ssl, client.fd);   /* bind to the wolfIP fd */
if (ret != 0) { /* setup error */ }

/* Drive the handshake non-blocking (see section 8) */
ret = wolfSSL_connect(client.ssl);
if (ret != WOLFSSL_SUCCESS) {
    int err = wolfSSL_get_error(client.ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
        /* handshake in progress: return and retry on the next poll cycle */
    }
}
```

After `wolfSSL_connect()` returns `WOLFSSL_SUCCESS`, use `wolfSSL_read()` /
`wolfSSL_write()` for application data — same `WANT_READ`/`WANT_WRITE` handling
applies.

## 7. Setting up a TLS server

A server adds an accept loop: a listening wolfIP socket, and one `WOLFSSL`
object per accepted connection. Create a TLS-server `WOLFSSL_CTX`, register the
wolfIP callbacks on it, load the certificate and private key, then `bind`,
`listen`, and accept. From `src/test/test_native_wolfssl.c`:

```c
server_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());

/* Register the wolfIP I/O callbacks on the CTX */
wolfSSL_SetIO_wolfIP_CTX(server_ctx, s);

/* Load the server certificate and private key (DER here; PEM also works) */
wolfSSL_CTX_use_certificate_buffer(server_ctx, server_der, server_der_len,
                                   SSL_FILETYPE_ASN1);
wolfSSL_CTX_use_PrivateKey_buffer(server_ctx, server_key_der, server_key_der_len,
                                  SSL_FILETYPE_ASN1);

listen_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0);
wolfIP_register_callback(s, listen_fd, server_cb, s);
/* ... wolfIP_sock_bind() + wolfIP_sock_listen() ... */
```

On a readable event on the listening socket, accept and bind a fresh `WOLFSSL`
object to the new fd (`test_native_wolfssl.c`, `server_cb`):

```c
if ((fd == listen_fd) && (event & CB_EVENT_READABLE) && (client_fd == -1)) {
    client_fd = wolfIP_sock_accept((struct wolfIP *)arg, listen_fd, NULL, NULL);
    if (client_fd > 0) {
        server_ssl = wolfSSL_new(server_ctx);
        wolfSSL_SetIO_wolfIP(server_ssl, client_fd);
        /* The first wolfSSL_read() drives the handshake; an explicit
         * wolfSSL_accept() is optional. */
    }
}
```

`test_native_wolfssl.c` lets the first `wolfSSL_read()` trigger the handshake
implicitly. The bare-metal demo `src/port/stm32h563/tls_server.c` instead drives
an explicit `wolfSSL_accept()` from a per-client state machine, which is the
clearer pattern for multiple concurrent clients (`tls_server.c`,
`tls_client_cb`):

```c
case TLS_CLIENT_STATE_HANDSHAKE:
    ret = wolfSSL_accept(client->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        client->state = TLS_CLIENT_STATE_CONNECTED;
    } else {
        err = wolfSSL_get_error(client->ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ &&
            err != WOLFSSL_ERROR_WANT_WRITE) {
            /* real failure: tear the client down */
            tls_client_free(client);
        }
        /* WANT_READ/WANT_WRITE: handshake continues on the next callback */
    }
    break;
```

In `tls_server.c` each accepted client gets its own slot, its own `WOLFSSL`
object, and its own per-fd wolfIP callback (`wolfIP_register_callback(stack,
client_fd, tls_client_cb, client)`), so several TLS sessions can be in flight at
once on a single stack.

## 8. Non-blocking handshakes and the poll loop

This is the crux of the integration. wolfIP is single-threaded and
event-driven: nothing blocks, and all socket progress happens inside
`wolfIP_poll()`. wolfSSL's handshake and data calls must therefore run in
non-blocking mode and be re-driven until they finish.

The contract, end to end:

1. The glue's recv/send callbacks return `WANT_READ`/`WANT_WRITE` whenever the
   socket would block (`wolfIP_sock_recv`/`send` returned `-WOLFIP_EAGAIN`).
2. wolfSSL therefore returns from `wolfSSL_connect`/`accept`/`read`/`write` with
   `wolfSSL_get_error()` equal to `WOLFSSL_ERROR_WANT_READ` or
   `WOLFSSL_ERROR_WANT_WRITE` instead of completing.
3. Your code must treat those two as "**not an error, retry later**": return to
   the event loop, call `wolfIP_poll()` (which actually moves bytes), and call
   the same wolfSSL function again on the next readable/writable event.

So the loop shape is always:

```text
   for (;;) {
       now_ms = monotonic_ms();
       wolfIP_poll(stack, now_ms);     /* moves ciphertext, fires callbacks */
       /* in the socket callback (or your state machine):
        *   ret = wolfSSL_connect/accept/read/write(ssl, ...)
        *   if WANT_READ/WANT_WRITE -> just return, retry next iteration
        *   if SUCCESS              -> advance state
        *   else                    -> error, tear down
        */
   }
```

The `tls_client_poll()` state machine in `src/port/stm32h563/tls_client.c` is the
canonical shape: `CONNECTING` polls `wolfIP_sock_connect` until it stops
returning `-WOLFIP_EAGAIN`, then `HANDSHAKE` calls `wolfSSL_connect` and stays in
that state while the error is `WANT_READ`/`WANT_WRITE`, then `CONNECTED` does
`wolfSSL_read`/`wolfSSL_write`. The same `WANT_*` rule applies to application
data, not just the handshake:

```c
ret = wolfSSL_read(client.ssl, client.rx_buf, sizeof(client.rx_buf) - 1);
if (ret > 0) {
    /* got plaintext */
} else {
    err = wolfSSL_get_error(client.ssl, ret);
    if (err == WOLFSSL_ERROR_ZERO_RETURN) {
        /* peer sent close_notify: clean shutdown */
    } else if (err != WOLFSSL_ERROR_WANT_READ) {
        /* real error */
    }
    /* WANT_READ: nothing to read yet, try again next poll */
}
```

> **Note.** Because the glue maps a non-`-WOLFIP_EAGAIN` failure to
> `WOLFSSL_CBIO_ERR_CONN_CLOSE`, a wolfSSL call that returns an error whose
> `wolfSSL_get_error()` is *neither* `WANT_READ`/`WANT_WRITE` *nor*
> `ZERO_RETURN` means the underlying wolfIP socket is gone — close and free the
> session rather than retrying.

## 9. Cleanup and the static descriptor pool

`wolfSSL_SetIO_wolfIP()` allocates a slot from a static array
(`io_descs[MAX_WOLFIP_CTX]` in `src/port/wolfssl_io.c`) to hold the
`{fd, stack}` binding for the session. That slot is **not** freed by
`wolfSSL_free()`. You must release it explicitly with
`wolfSSL_CleanupIO_wolfIP()` on **every** teardown path, before `wolfSSL_free`,
or the pool leaks one slot per connection and is exhausted after
`MAX_WOLFIP_CTX` sessions.

The correct order (`src/port/stm32h563/tls_server.c`, `tls_client_free`):

```c
if (client->ssl) {
    wolfSSL_shutdown(client->ssl);
    wolfSSL_CleanupIO_wolfIP(client->ssl);   /* release the io_descs[] slot */
    wolfSSL_free(client->ssl);
    client->ssl = NULL;
}
if (client->fd >= 0) {
    wolfIP_sock_close(server.stack, client->fd);
    client->fd = -1;
}
```

`MAX_WOLFIP_CTX` (default 8) caps both the number of registered `WOLFSSL_CTX`
stacks and the number of *simultaneously live* TLS sessions. If you need more
concurrent connections, raise it at compile time and ensure the cleanup call is
on every path (handshake failure, read error, normal close).

## 10. Troubleshooting

**`wolfSSL_SetIO_wolfIP()` returns `WOLFSSL_CBIO_ERR_GENERAL`.** The CTX has no
registered stack — you called it before `wolfSSL_SetIO_wolfIP_CTX(ctx, stack)`,
or on a CTX that was never registered. Register the CTX first.

**`wolfSSL_SetIO_wolfIP()` returns `-1`.** Either `ssl` is NULL / `fd < 0`, or
the static descriptor pool is full. The pool fills when sessions are torn down
without `wolfSSL_CleanupIO_wolfIP()` (§9) — audit every close path — or you have
more than `MAX_WOLFIP_CTX` live sessions; raise the limit.

**The handshake never completes / stalls in `WANT_READ` or `WANT_WRITE`.** You
are not re-driving wolfSSL after polling. `WANT_READ`/`WANT_WRITE` is normal and
expected on every non-blocking handshake; the call must be retried on the next
`wolfIP_poll()` iteration when the socket is readable/writable. Make sure
`wolfIP_poll()` is being called in the loop and that `now_ms` advances — without
it no bytes ever move and the handshake hangs forever.

**The connection dies immediately mid-handshake.** A wolfSSL error whose
`wolfSSL_get_error()` is not `WANT_READ`/`WANT_WRITE`/`ZERO_RETURN` means the
glue reported `CONN_CLOSE` — the wolfIP socket was reset or never established.
Confirm the TCP `connect`/`accept` actually completed (stop returning
`-WOLFIP_EAGAIN`) *before* the first `wolfSSL_connect`/`accept`.

**Server: "no certificate" / handshake fails after ClientHello.** The server
CTX has no cert/key. Load both with
`wolfSSL_CTX_use_certificate_buffer()` and `wolfSSL_CTX_use_PrivateKey_buffer()`
(or the file variants) *before* accepting, and match `SSL_FILETYPE_ASN1` (DER)
vs `WOLFSSL_FILETYPE_PEM` to your buffer format.

**Client: certificate verification fails.** Load the issuing CA with
`wolfSSL_CTX_load_verify_buffer()` and keep `WOLFSSL_VERIFY_PEER`. The
`tls_client.c` demo uses `WOLFSSL_VERIFY_NONE` for bring-up only — do not ship
that. Also set SNI with `wolfSSL_UseSNI()`; most public servers require it.

**Link errors on `wolfSSL_*`.** `src/port/wolfssl_io.c` was not compiled with
`-DWOLFSSL_WOLFIP`, or you did not link `-lwolfssl`. See §2.

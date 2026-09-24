# Certificate enrolment (wolfCert) How-To

wolfCert is wolfSSL's certificate enrolment library: it speaks EST (RFC 7030)
and SCEP (RFC 8894) to a CA and hands back an issued certificate. This guide
covers running it on wolfIP, so a device with no BSD sockets can enrol.

It is a getting-started document, not a reference manual. The authoritative
glue is `src/port/wolfcert_io.c` (declared in `wolfip.h` under
`WOLFCERT_WOLFIP`). The wolfCert API itself — `wolfcert_est_simple_enroll()`,
`wolfcert_scep_*`, key and CSR generation — is documented by wolfCert; this
guide only covers the wolfIP integration points.

## Table of Contents

- [1. What the integration provides](#1-what-the-integration-provides)
- [2. Building with wolfCert support](#2-building-with-wolfcert-support)
- [3. Registering the transport](#3-registering-the-transport)
- [4. The transport callbacks](#4-the-transport-callbacks)
- [5. Name resolution](#5-name-resolution)
- [6. Timeouts and the poll loop](#6-timeouts-and-the-poll-loop)
- [7. Troubleshooting](#7-troubleshooting)

---

## 1. What the integration provides

wolfCert opens its own connections, so it exposes a `WolfCertTransport` vtable
— `connect`, `read`, `write`, `disconnect` — that a stack without BSD sockets
fills in. `src/port/wolfcert_io.c` is wolfIP's implementation of that vtable,
in the same spirit as `src/port/wolfssl_io.c` for wolfSSL.

One transport carries every protocol wolfCert speaks:

| Deployment | Covered |
|---|---|
| EST over HTTPS | yes |
| SCEP over HTTPS | yes |
| SCEP over plain HTTP | yes |

TLS records travel through the same `read`/`write` as plain HTTP, so the rows
above are all carried by wolfIP end to end and the glue needs no TLS code of
its own.

`src/port/wolfssl_io.c` and `WOLFSSL_WOLFIP` are a different integration —
running wolfSSL directly on wolfIP sockets, see
[TLS over wolfIP](tls_howto.md). They are not needed here, and an application
can use both.

## 2. Building with wolfCert support

The integration is gated by **`WOLFCERT_WOLFIP`** and lives in one source
file, `src/port/wolfcert_io.c`, which you compile in and link against
`-lwolfcert` (and `-lwolfssl`, which wolfCert requires).

1. Build and install wolfCert first.
2. Compile `src/port/wolfcert_io.c` together with your application.
3. Add `-DWOLFCERT_WOLFIP` to the wolfIP/application `CFLAGS`, so the
   declarations in `wolfip.h` are exposed.
4. Link with `-lwolfcert -lwolfssl`.

On a device with no sockets and no filesystem, wolfCert can also drop its own
POSIX transport and file store; see wolfCert's `docs/EMBEDDED.md` for those
build options.

When `WOLFCERT_WOLFIP` is defined, `wolfip.h` declares the two entry points:

```c
void *wolfCert_Init_wolfIP(WolfCertTransport *t, struct wolfIP *stack,
                           uint64_t (*now_ms)(void));
void  wolfCert_Cleanup_wolfIP(void *context);
```

One compile-time knob, `MAX_WOLFCERT_CTX` (default 2, in
`src/port/wolfcert_io.c`), sizes the static context pool.

## 3. Registering the transport

`wolfCert_Init_wolfIP()` opens nothing. It fills in a transport you own and
returns a context handle for the matching cleanup call:

```c
static WolfCertTransport wc_transport;
static void *wc_io;

static uint64_t my_now_ms(void)
{
    return board_get_tick();     /* the clock you already feed wolfIP_poll() */
}

wc_io = wolfCert_Init_wolfIP(&wc_transport, ipstack, my_now_ms);
if (wc_io == NULL)
    return -1;                   /* bad arguments, or the pool is full */

cfg.transport = wc_transport;    /* WolfCertServerCfg, WolfCertHttpSessionCfg
                                  * or WolfCertHttpRequest */
```

Call `wolfCert_Cleanup_wolfIP(wc_io)` when you are done with the stack, to
release the pool slot.

`now_ms` returns milliseconds and must advance. It is the transport's only
clock and bounds every timeout, so one that never moves leaves the transport
waiting with no deadline.

## 4. The transport callbacks

wolfCert calls these; your application does not. `read` and `write` map
wolfIP's return codes like this:

| `wolfIP_sock_recv`/`send` returns | Reported as |
|---|---|
| `> 0` | the byte count — short transfers are passed through |
| `0` (receive only) | `WOLFCERT_ERR_CONN_CLOSED` — the peer closed |
| `-1` | `WOLFCERT_ERR_CONN_CLOSED` — the socket is no longer established |
| `-WOLFIP_EAGAIN` | `WANT_READ`/`WANT_WRITE`, or poll and retry when blocking |
| `-WOLFIP_EINVAL` | `WOLFCERT_ERR_BAD_ARG` |
| anything else | `WOLFCERT_ERR_IO` |

`connect` does not use this mapping. It reports `WOLFCERT_ERR_BAD_ARG` for a
host or port it will not accept, `WOLFCERT_ERR_CONN_CLOSED` when the peer
refuses the connection, and `WOLFCERT_ERR_IO` for every other failure,
including a name that does not resolve.

The connection handle is the wolfIP descriptor, handed back as an opaque
pointer. `disconnect` closes it.

## 5. Name resolution

`connect` accepts either a dotted quad or a hostname. A dotted quad is parsed
locally; a hostname goes to `nslookup()` and the answer is awaited inside
`connect`.

**Only one hostname lookup runs at a time, even if you created several
transport contexts.** `connect` runs to completion before returning, so under
wolfIP's single-threaded model lookups cannot overlap.

Two behaviours of the resolver shape what a failed lookup costs here — a name
that does not exist is never reported, only timed out, and an abandoned query
clears on its own schedule rather than being cancelled. Both are described in
[DHCP & DNS clients](dhcp_dns_howto.md); the practical effect is that a failed
resolution spends the connect budget, and retrying at once can spend part of
the next one.

Prefer keeping the hostname in the URL over an IP literal, so the server
certificate is verified against the name.

## 6. Timeouts and the poll loop

`connect`, and any blocking `read`/`write`, drive `wolfIP_poll()` themselves,
so your own loop does not run until they return. wolfIP's socket callbacks
still do — including your application's, from inside the transport's wait.
They poll back to back without sleeping, so the CPU stays busy until they
return. Two compile-time defaults bound these calls:

| Macro | Default | Applies to |
|---|---|---|
| `WOLFCERT_WOLFIP_CONNECT_TIMEOUT_MS` | 30000 | `connect`, including resolution |
| `WOLFCERT_WOLFIP_IO_TIMEOUT_MS` | 30000 | blocking `read`/`write` |

**On an MCU, keep both inside your watchdog period** — a few seconds.
`cfg.timeout_ms` overrides the connect default; blocking reads and writes
always use `WOLFCERT_WOLFIP_IO_TIMEOUT_MS`. A refused connection fails at
once; an unreachable peer, which never answers, costs the full budget.

Where wolfCert offers a non-blocking mode, prefer it: `read` and `write` then
return immediately instead of polling internally, leaving your own loop to
pace the stack, as in [TLS over wolfIP](tls_howto.md) section 8. The connect
is synchronous either way.

## 7. Troubleshooting

**Link errors on `wolfCert_Init_wolfIP`.** `src/port/wolfcert_io.c` was not
compiled, or `-DWOLFCERT_WOLFIP` was not passed. See section 2.

**`wolfCert_Init_wolfIP()` returns NULL.** A NULL argument, or more transports
than `MAX_WOLFCERT_CTX`.

**Requests fail immediately with a bad-argument error.** The config carries no
transport, or the URL's host is empty.

**Connects always take the full timeout.** The peer is not answering, or the
name does not resolve; check the route and the DNS server.

**Blocking reads or writes fail with an I/O error.** The server took longer
than `WOLFCERT_WOLFIP_IO_TIMEOUT_MS` to respond; raise it.

**A connect never returns.** `now_ms` is not advancing; see section 3.

**EST enrolment fails with a TLS error.** EST requires the client to
authenticate the server; check wolfCert's trust-anchor settings.

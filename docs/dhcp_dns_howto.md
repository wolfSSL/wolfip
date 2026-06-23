# DHCP & DNS Client How-To

This guide shows how to bring a wolfIP interface up automatically with the
**DHCP client** (RFC 2131) and how to resolve hostnames with the **DNS client**
(RFC 1035): how to start each one, how they make progress inside your poll loop,
how to read the results, and how to chain "get a lease, then resolve a host"
into a single startup sequence.

It is a getting-started document, not a reference manual. The authoritative API
is `wolfip.h`; the worked examples come from `src/test/test_dhcp_dns.c` (a
full DHCP-then-DNS-then-connect test driven against `dnsmasq`) and
`src/port/stm32h563/main.c` (a bare-metal DHCP bring-up).

## Table of Contents

- [1. What the DHCP and DNS clients do (and do not)](#1-what-the-dhcp-and-dns-clients-do-and-do-not)
- [2. Mental model: everything happens inside `wolfIP_poll()`](#2-mental-model-everything-happens-inside-wolfip_poll)
- [3. The API](#3-the-api)
- [4. DHCP: acquiring a lease](#4-dhcp-acquiring-a-lease)
- [5. DHCP: lease lifecycle and renewal](#5-dhcp-lease-lifecycle-and-renewal)
- [6. DNS: configuring the resolver](#6-dns-configuring-the-resolver)
- [7. DNS: resolving a name](#7-dns-resolving-a-name)
- [8. End-to-end: DHCP up, then resolve a host](#8-end-to-end-dhcp-up-then-resolve-a-host)
- [9. Socket-pool implications](#9-socket-pool-implications)
- [10. Troubleshooting](#10-troubleshooting)

---

## 1. What the DHCP and DNS clients do (and do not)

wolfIP ships a **DHCP client** and a **DNS client**. Both are *client only* — there
is no DHCP server and no DNS server in the stack.

The DHCP client implements the RFC 2131 four-message bring-up
(DISCOVER → OFFER → REQUEST → ACK) over UDP ports 68/67. On a successful ACK it
configures the primary interface's IP address, subnet mask and gateway, and (if
the server provided DHCP option 6) records a DNS server address. It then tracks
the lease and renews/rebinds it automatically.

The DNS client implements RFC 1035 forward lookups (A records) over UDP port 53.
You hand it a hostname and a callback; when an answer arrives the callback fires
with the resolved IPv4 address. (A companion reverse-lookup function,
`wolfIP_dns_ptr_lookup()`, resolves PTR records to a name; the rest of this guide
focuses on the forward `nslookup()` path.)

**Not** supported: acting as a DHCP or DNS server, IPv6 / AAAA records, more than
one outstanding DNS query at a time, caching of DNS answers, and TCP-based DNS
(truncated `TC` responses are dropped, not retried over TCP).

## 2. Mental model: everything happens inside `wolfIP_poll()`

Neither client blocks and neither spawns a thread. Both are driven entirely by
your normal `wolfIP_poll(s, now_ms)` loop:

- `dhcp_client_init()` / `nslookup()` open a UDP socket, register an internal
  callback on it, and send the first packet.
- Every later step — receiving an OFFER/ACK, sending the REQUEST, firing the
  resolve callback, retransmitting on timeout, renewing the lease — happens when
  `wolfIP_poll()` dispatches that UDP socket's readable event or services a
  timer.

```text
   your loop:  wolfIP_poll(s, now_ms)  ──┐
                                         │ drains DHCP/DNS UDP sockets
                                         │ runs DHCP discover/request timers
                                         │ runs DHCP lease + DNS retransmit timers
   ┌─────────────────────────────────────┘
   ▼
   dhcp_callback() ──▶ parse OFFER/ACK ──▶ set ip/mask/gw, dns_server, state=BOUND
   dns_callback()  ──▶ parse A record   ──▶ lookup_cb(ip)
```

So the universal pattern is: kick off the operation once, then keep calling
`wolfIP_poll()` while polling a completion predicate (`dhcp_bound()`) or waiting
for a callback (`nslookup`). If `now_ms` does not advance between polls, the
retransmit and lease timers never fire.

## 3. The API

All declarations are in `wolfip.h`:

```c
/* DHCP client */
int dhcp_client_init(struct wolfIP *s);
int dhcp_bound(struct wolfIP *s);
int dhcp_client_is_running(struct wolfIP *s);
int wolfIP_dns_server_get(struct wolfIP *s, ip4 *dns_server);

/* DNS client */
int nslookup(struct wolfIP *s, const char *name, uint16_t *id,
             void (*lookup_cb)(uint32_t ip));
```

| Function | Returns | Meaning |
|----------|---------|---------|
| `dhcp_client_init(s)` | `0` on the first DISCOVER sent, negative on error | Opens/binds the DHCP UDP socket, picks a random transaction ID, and sends DISCOVER. Refuses (returns `-1`) if a DHCP session is already running. |
| `dhcp_bound(s)` | non-zero if a lease is held | True when state is `BOUND`, `RENEWING` or `REBINDING` — i.e. a usable IP is configured. |
| `dhcp_client_is_running(s)` | non-zero while in progress | True while DHCP is active but **not yet** bound (DISCOVER/REQUEST in flight). Useful as a loop guard so you stop polling if the client gives up. |
| `wolfIP_dns_server_get(s, &dns)` | `0` on success, `-WOLFIP_EINVAL` on null args | Reads back the DNS server address currently in effect (learned via DHCP or set statically). `0.0.0.0` means none is set. |
| `nslookup(s, name, &id, cb)` | `0` if the query was sent, negative otherwise | Sends an A-record query for `name`; `id` receives the DNS transaction ID; `cb(ip)` fires later with the answer (`ip` in host byte order). |

`nslookup()` error returns worth knowing (from `src/wolfip.c`):

| Value | Cause |
|-------|-------|
| `-22` | Invalid argument (null `s`/`name`/`id`/`cb`, or a name longer than 255 bytes / label longer than 63). |
| `-16` | A DNS query is already in progress (only one at a time). |
| `-101` | No DNS server configured (`dns_server == 0`). |

## 4. DHCP: acquiring a lease

The whole client-side sequence is: call `dhcp_client_init()` once, then poll
until `dhcp_bound()` is true. From `src/test/test_dhcp_dns.c`:

```c
gettimeofday(&tv, NULL);
wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
dhcp_client_init(s);
do {
    gettimeofday(&tv, NULL);
    wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    usleep(1000);
    wolfIP_ipconfig_get(s, &ip, &nm, &gw);
} while (!dhcp_bound(s));
printf("DHCP: obtained IP address.\n");
wolfIP_ipconfig_get(s, &ip, &nm, &gw);
```

Once `dhcp_bound()` returns true, `wolfIP_ipconfig_get(s, &ip, &nm, &gw)`
(`wolfip.h`) returns the leased address, mask and gateway — the same call you
would use after a static `wolfIP_ipconfig_set()`. The values are `ip4` in
network byte order.

On constrained targets you usually also want a safety net: bound the wait so a
network with no DHCP server does not loop forever. The STM32H5 port
(`src/port/stm32h563/main.c`) combines `dhcp_bound()` with
`dhcp_client_is_running()` and a tick timeout:

```c
dhcp_ret = dhcp_client_init(IPStack);
if (dhcp_ret < 0) {
    /* DHCP init failed: socket pool full, or already running */
} else {
    dhcp_start_tick = tick;
    while (!dhcp_bound(IPStack) && dhcp_client_is_running(IPStack)) {
        (void)wolfIP_poll(IPStack, tick);
        tick++;
        delay(8000);                        /* ~1 ms per iteration */
        if ((tick - dhcp_start_tick) > dhcp_timeout)
            break;                          /* safety-net timeout */
    }
    if (dhcp_bound(IPStack)) {
        ip4 ip = 0, nm = 0, gw = 0;
        wolfIP_ipconfig_get(IPStack, &ip, &nm, &gw);
        /* ... use ip/nm/gw ... */
    }
}
```

The `dhcp_client_is_running()` guard matters: if the DISCOVER and REQUEST retries
are exhausted the client returns to the `OFF` state, at which point
`dhcp_client_is_running()` goes false and the loop exits even though
`dhcp_bound()` never became true.

Internally (`src/wolfip.c`), DISCOVER and REQUEST each retry up to three times
(`DHCP_DISCOVER_RETRIES` / `DHCP_REQUEST_RETRIES`, default `3`) with a
2-second base timeout (`DHCP_DISCOVER_TIMEOUT` / `DHCP_REQUEST_TIMEOUT`) and an
exponential backoff capped at `DHCP_BACKOFF_MAX_MS` (64 s). A `DHCPNAK` in
response to a REQUEST restarts the whole process from DISCOVER.

## 5. DHCP: lease lifecycle and renewal

A bound lease is not the end of the story. When the ACK is parsed
(`dhcp_parse_ack()` in `src/wolfip.c`) the client requires the mandatory
lease-time option (51) and arms timers from the renewal (T1) and rebind (T2)
times the server supplied. The state machine then moves:

```text
   DISCOVER_SENT ─OFFER─▶ REQUEST_SENT ─ACK─▶ BOUND
                                                │ T1 expires
                                                ▼
                                            RENEWING ─(no reply by T2)─▶ REBINDING
                                                │                            │
                                            ACK │                        ACK │
                                                ▼                            ▼
                                              BOUND ◀────────────────────────┘
```

You do **not** call anything to renew — it happens inside `wolfIP_poll()` as the
timers fire. Note that `dhcp_bound()` deliberately returns true in `RENEWING`
and `REBINDING` as well as `BOUND`, because the address remains valid and usable
throughout renewal. If both renewal and rebinding fail before the lease expires,
the client tears the configuration down and returns to `OFF`.

The DNS server learned from DHCP option 6 is stored at this point too, but only
if one is not already set (a statically configured DNS server is **not**
overwritten by DHCP — see §6).

## 6. DNS: configuring the resolver

`nslookup()` needs a DNS server address. There are two ways it gets one:

1. **Learned from DHCP.** If the DHCP ACK carried option 6 (Domain Name Server)
   *and* no DNS server was already configured, the client records the first
   server. After `dhcp_bound()` you can read it back:

   ```c
   ip4 dns = 0;
   wolfIP_dns_server_get(s, &dns);   /* 0 == none set */
   ```

2. **Configured statically at compile time.** Define `WOLFIP_STATIC_DNS_IP` in
   `config.h`. The default configuration sets it to Quad9:

   ```c
   /* config.h */
   #define WOLFIP_STATIC_DNS_IP "9.9.9.9"
   ```

   `wolfIP_init_static()` applies it once at startup, **only if** the stack does
   not already have a DNS server (`src/wolfip.c`):

   ```c
   if (wolfIP_static.dns_server == 0) {
   #ifdef WOLFIP_STATIC_DNS_IP
       wolfIP_static.dns_server = atoip4(WOLFIP_STATIC_DNS_IP);
   #endif
   }
   ```

Because the static value is applied first and DHCP only fills the slot when it is
still zero, a compile-time `WOLFIP_STATIC_DNS_IP` takes precedence over whatever
DHCP offers. Leave it undefined (and rely on DHCP) if you want the network to
choose the resolver. If neither path sets a server, `nslookup()` returns `-101`.

## 7. DNS: resolving a name

A lookup is a single non-blocking call plus a completion callback. The callback
has signature `void (*)(uint32_t ip)`, where `ip` is the resolved IPv4 address in
**host byte order**. From `src/test/test_dhcp_dns.c`:

```c
static int example_com_resolved = 0;

void ns_cb(uint32_t ip)
{
    printf("Obtained ip address for example.com: %s\n",
           inet_ntoa(*(struct in_addr *)&ip));
    example_com_resolved = 1;
}

/* ... */
uint16_t dns_id;
nslookup(s, "example.com", &dns_id, ns_cb);

while (!example_com_resolved) {
    gettimeofday(&tv, NULL);
    wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    usleep(1000);
}
```

Behaviour to rely on (verified in `src/wolfip.c`):

- **One query at a time.** `nslookup()` returns `-16` if a query is already
  outstanding. The slot frees when the callback fires or the query is aborted.
- **The transaction ID** written to `*id` is a random non-zero 16-bit value; the
  response is dropped unless its ID matches, so a stale reply for an old query is
  ignored.
- **When the callback fires.** `dns_callback()` runs inside `wolfIP_poll()` when
  the answer datagram arrives. It walks the answer section and, on the first A
  record (type A, class IN) it finds, invokes your `lookup_cb(ip)` exactly once,
  then clears the query state.
- **The callback does not fire on failure.** A server error (`RCODE != 0`), a
  truncated (`TC`) response, or exhausting the retransmit budget aborts the
  query silently — the callback is simply never called. Time-box your wait
  accordingly.
- **Retransmits.** The query is resent up to `DNS_QUERY_RETRIES` (default `3`)
  times on a ~2 s timer (`DNS_QUERY_TIMEOUT`, with a jittered first interval)
  before the query is abandoned.

## 8. End-to-end: DHCP up, then resolve a host

Putting §4 and §7 together gives the canonical startup sequence used in
`src/test/test_dhcp_dns.c`: bring the interface up with DHCP, then resolve a name
(using the DNS server DHCP just handed us, or the static fallback), then connect.

```c
/* 1. Acquire a lease. */
dhcp_client_init(s);
do {
    gettimeofday(&tv, NULL);
    wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    usleep(1000);
} while (!dhcp_bound(s));
wolfIP_ipconfig_get(s, &ip, &nm, &gw);     /* leased address now valid */

/* 2. Resolve a hostname. */
nslookup(s, "example.com", &dns_id, ns_cb);
while (!example_com_resolved) {
    gettimeofday(&tv, NULL);
    wolfIP_poll(s, tv.tv_sec * 1000 + tv.tv_usec / 1000);
    usleep(1000);
}

/* 3. ns_cb stashed the address; open a socket and connect to it as usual. */
```

In the test the resolved address is then used to drive an echo client
(`test_wolfip_echoclient(s)`). The single shared `wolfIP_poll()` loop services
DHCP, DNS and the application sockets together — there is no separate "DHCP
thread" or "DNS thread".

> Illustrative glue: in real code, have `ns_cb` save the `ip` into a global or
> a context struct (it is host byte order — convert with `ee32()` before placing
> it in a `wolfIP_sockaddr_in.sin_addr`) rather than only printing it, so step 3
> can connect to it.

## 9. Socket-pool implications

Both clients consume entries from the **UDP socket pool**, sized by
`MAX_UDPSOCKETS` (`config.h`, default `2`):

- `dhcp_client_init()` allocates one UDP socket (bound to port 68) for the
  lifetime of the DHCP client.
- The first `nslookup()` (or `wolfIP_dns_ptr_lookup()`) lazily allocates one UDP
  socket on port 53 and keeps it for reuse by later lookups.

So if your application also opens UDP sockets, budget for DHCP (+1) and DNS (+1)
on top of your own. With the default `MAX_UDPSOCKETS 2`, enabling **both** DHCP
and DNS consumes the entire default pool — raise `MAX_UDPSOCKETS` in `config.h`
if your application needs UDP sockets of its own. If the pool is exhausted,
`dhcp_client_init()` returns negative and `nslookup()` fails to allocate its
socket.

## 10. Troubleshooting

**DHCP never gets bound.** Confirm `now_ms` advances between `wolfIP_poll()`
calls — the DISCOVER/REQUEST retransmit timers are time-driven, so a frozen clock
stalls the handshake. Check that the link is up and that DISCOVER broadcasts
(255.255.255.255:67) are reaching a server. After the retry budget the client
returns to `OFF`; use `dhcp_client_is_running()` as a loop guard to detect this
instead of spinning forever on `!dhcp_bound()`.

**`dhcp_client_init()` returns negative.** Either DHCP is already running
(returns `-1`), or the UDP socket pool is full — raise `MAX_UDPSOCKETS`.

**Lease binds but no DNS works.** The server may not have sent option 6. Read it
back with `wolfIP_dns_server_get()`; if it is `0.0.0.0`, set
`WOLFIP_STATIC_DNS_IP` in `config.h` as a fallback.

**`nslookup()` returns `-101`.** No DNS server is configured. Either you called
it before `dhcp_bound()` populated option 6, or DHCP never supplied one and
`WOLFIP_STATIC_DNS_IP` is undefined.

**`nslookup()` returns `-16`.** A previous query is still outstanding. Wait for
its callback (or its timeout to abort it) before issuing another — only one DNS
query runs at a time.

**The resolve callback never fires.** This is the *expected* outcome on failure:
NXDOMAIN / server error (`RCODE != 0`), a truncated (`TC`) reply, or three timed-out
retransmits all abort the query without calling back. Do not wait unboundedly on
the callback flag — pair it with a timeout. Also confirm the DNS server address
is reachable and that `wolfIP_poll()` keeps running so the answer datagram is
drained.

**Wrong-looking resolved address.** The callback delivers `ip` in **host byte
order**; convert with `ee32()` before storing it in a `sin_addr` (which is network
byte order).

# Advanced IPv4 How-To

This guide shows how to use wolfIP's **advanced IPv4 features**: UDP multicast
with IGMP membership reports, IPv4 forwarding between interfaces, multi-interface
configuration, and the internal loopback interface. Each feature is opt-in and
removed by the preprocessor when disabled, so the default single-interface
endpoint build is unchanged.

It is a getting-started document, not a reference manual. The authoritative API
is `wolfip.h` (with the compile-time switches in `config.h`); the worked
examples come from `src/test/test_multicast_interop.c`,
`src/test/unit/unit_tests_multicast.c`, and `src/test/test_wolfssl_forwarding.c`.

## Table of Contents

- [1. Multicast and IGMP](#1-multicast-and-igmp)
- [2. IPv4 forwarding](#2-ipv4-forwarding)
- [3. Multiple interfaces](#3-multiple-interfaces)
- [4. The loopback interface](#4-the-loopback-interface)
- [5. Troubleshooting](#5-troubleshooting)

---

## 1. Multicast and IGMP

IPv4 UDP multicast is compiled out by default. Define `IP_MULTICAST` to enable
the BSD-style multicast socket options and the IGMPv3 any-source-multicast (ASM)
membership reports. When the macro is undefined, none of the multicast code or
state is built into the stack.

The socket options are exposed under wolfIP-prefixed names so they resolve to the
host's `IP_*` constants when those headers are present and to fixed fallback
values otherwise (`wolfip.h`):

| Option | Fallback value | `optval` type | Meaning |
|--------|---------------|---------------|---------|
| `WOLFIP_IP_ADD_MEMBERSHIP` | 35 | `struct wolfIP_ip_mreq` | Join a multicast group on an interface. |
| `WOLFIP_IP_DROP_MEMBERSHIP` | 36 | `struct wolfIP_ip_mreq` | Leave a previously joined group. |
| `WOLFIP_IP_MULTICAST_IF` | 32 | `struct wolfIP_mreq_addr` | Pin the egress interface for multicast sends. |
| `WOLFIP_IP_MULTICAST_TTL` | 33 | `int` or `uint8_t` | TTL for outgoing multicast datagrams. |
| `WOLFIP_IP_MULTICAST_LOOP` | 34 | `int` or `uint8_t` | Deliver this socket's own multicast sends back to local members. |

All multicast options use socket level `WOLFIP_SOL_IP`, and they apply only to
**UDP** sockets. The `struct wolfIP_ip_mreq` / `struct wolfIP_mreq_addr` types are
defined in `wolfip.h`:

```c
struct wolfIP_mreq_addr {
    uint32_t s_addr;
};

struct wolfIP_ip_mreq {
    struct wolfIP_mreq_addr imr_multiaddr;   /* the group address      */
    struct wolfIP_mreq_addr imr_interface;   /* local iface IP, or ANY */
};
```

The `s_addr` fields are in **network byte order** — fill them with `inet_pton()`
or `htonl()`, exactly as with a host `struct ip_mreq`.

### Joining a group

To receive multicast, bind a UDP socket to the destination port, then join the
group with `WOLFIP_IP_ADD_MEMBERSHIP`. From `src/test/test_multicast_interop.c`:

```c
wolf_fd = wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_DGRAM, 17);

memset(&bind_addr, 0, sizeof(bind_addr));
bind_addr.sin_family = AF_INET;
bind_addr.sin_port = htons(MCAST_PORT);
bind_addr.sin_addr.s_addr = 0;
wolfIP_sock_bind(s, wolf_fd, (struct wolfIP_sockaddr *)&bind_addr,
                 sizeof(bind_addr));

memset(&mreq, 0, sizeof(mreq));
inet_pton(AF_INET, MCAST_GROUP, &mreq.imr_multiaddr.s_addr);
mreq.imr_interface.s_addr = htonl(INADDR_ANY);   /* let routing pick the iface */
wolfIP_sock_setsockopt(s, wolf_fd, WOLFIP_SOL_IP,
                       WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
```

`imr_interface` selects the interface:

- `INADDR_ANY` resolves the interface from the route to the group, and that
  interface **must already have a configured source IP** — the join is rejected
  with `-WOLFIP_EINVAL` otherwise, because there would be no valid source address
  to build the IGMP report from (`mcast_if_from_addr`, `src/wolfip.c`).
- A specific local-interface IP pins the membership to that interface.

A datagram for a joined group is delivered only after the join: an unjoined
socket bound to the same port does not receive the group's traffic.

### IGMP report behavior

The join/leave path is driven by the membership table in `struct wolfIP`
(`src/wolfip.c`), and emits IGMPv3 reports automatically:

- **On the first join** of a `{interface, group}` pair, wolfIP sends an IGMPv3
  Current-State Report with record type `MODE_IS_EXCLUDE` (an ASM join). The
  report is sent to the IGMPv3 all-routers address `224.0.0.22`
  (`igmp_send_report`).
- Memberships are **reference-counted**: multiple sockets joining the same
  `{interface, group}` share one membership entry, so only the first join and the
  last leave hit the wire.
- **On the last leave**, wolfIP sends a `CHANGE_TO_INCLUDE` report (the ASM
  leave).
- **Incoming IGMP Membership Queries** are answered, but not synchronously. Per
  RFC 3376 §5.2, wolfIP schedules a Current-State Report after a random delay
  drawn from the query's Max-Response-Time window, which coalesces a query flood
  into one deferred report per group (`igmp_input`, `igmp_report_timer_cb`).
- A query is accepted only if it arrives with IP **TTL 1** and is addressed to
  `224.0.0.1` (all-hosts) or to the group itself; anything else is dropped as
  off-link or spoofed.

### Sending multicast

To transmit, set the desired TX options and `sendto()` the group address. The
default multicast TTL is `1` and loopback defaults to `1` for a new UDP socket
(`src/wolfip.c`). From `src/test/test_multicast_interop.c`:

```c
int ttl = 3;
wolfIP_sock_setsockopt(s, wolf_fd, WOLFIP_SOL_IP,
                       WOLFIP_IP_MULTICAST_TTL, &ttl, sizeof(ttl));

memset(&dst, 0, sizeof(dst));
dst.sin_family = AF_INET;
dst.sin_port = htons(WOLFIP_MCAST_PORT);
inet_pton(AF_INET, MCAST_GROUP, &dst.sin_addr.s_addr);
wolfIP_sock_sendto(s, wolf_fd, payload, sizeof(payload), 0,
                   (struct wolfIP_sockaddr *)&dst, sizeof(dst));
```

Two more TX controls:

- `WOLFIP_IP_MULTICAST_IF` pins the egress interface (by local-interface IP) for
  this socket's multicast sends. Passing `INADDR_ANY` clears the pin and reverts
  to per-destination routing.
- `WOLFIP_IP_MULTICAST_LOOP` controls local delivery of the socket's own sends.
  When enabled (the default), a multicast datagram is looped back to local group
  members **after a successful wire send**, inside `wolfIP_poll()`
  (`src/wolfip.c`). A single socket that both joined a group and sent to it can
  therefore read its own datagram back:

```c
/* unit_tests_multicast.c: join + set TTL/LOOP, send, poll, then recv self */
wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP, WOLFIP_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP, WOLFIP_IP_MULTICAST_TTL,  &ttl,  sizeof(ttl));
wolfIP_sock_setsockopt(&s, sd, WOLFIP_SOL_IP, WOLFIP_IP_MULTICAST_LOOP, &loop, sizeof(loop));
wolfIP_sock_sendto(&s, sd, payload, sizeof(payload), 0, (struct wolfIP_sockaddr *)&dst, sizeof(dst));
wolfIP_poll(&s, 1);                                  /* drives the wire send + loopback */
wolfIP_sock_recvfrom(&s, sd, out, sizeof(out), 0, NULL, NULL);   /* reads its own datagram */
```

### Testing

The repository ships a Linux interop test that creates a TAP interface
(`wmcast0`) and validates both directions — Linux sending to a wolfIP receiver
and wolfIP sending to a Linux receiver (`src/test/test_multicast_interop.c`):

```sh
make unit-multicast
./build/test/unit

make build/test-multicast-interop
sudo ./build/test-multicast-interop
```

Per-membership compile-time sizing (`src/wolfip.c`): each UDP socket holds up to
`WOLFIP_UDP_MCAST_MEMBERSHIPS` (default 4) joins, and the stack-wide table holds
`MAX_UDPSOCKETS * WOLFIP_UDP_MCAST_MEMBERSHIPS` distinct memberships.

## 2. IPv4 forwarding

By default wolfIP is an endpoint and does not route. Set
`WOLFIP_ENABLE_FORWARDING` to `1` at compile time (default `0` in `config.h`) to
turn the stack into a simple IPv4 router between its interfaces.

Forwarding is inherently multi-interface: `wolfIP_forward_interface()` returns
`-1` whenever `if_count < 2` (`src/wolfip.c`), so a useful forwarding build also
needs `WOLFIP_MAX_INTERFACES >= 2` (see [section 3](#3-multiple-interfaces)).

### How a packet is forwarded

When a frame arrives whose destination is **not** local to the receiving
interface, the IP input path asks `wolfIP_forward_interface()` for an egress
interface. That lookup covers both:

- directly connected subnets on the stack's other interfaces, and
- optional static routes added with `wolfIP_route_add()`.

If a route is found, the packet is forwarded out that interface:

```text
   in_if  ─▶ IP input ─▶ dest local to this host? ─yes▶ deliver up the stack
                              │ no
                              ▼
                  forward_interface(in_if, dest)
                              │  (connected-subnet or static-route lookup)
                  ┌───────────┴───────────┐
                  │ no out iface           │ out iface found
                  ▼                        ▼
              (dropped)            ttl <= 1 ? ─yes▶ ICMP TTL-exceeded back to src
                                       │ no
                                       ▼
                              ttl--, recompute IP checksum,
                              ARP-resolve next hop, send on out_if
```

From the dispatch in `src/wolfip.c`:

```c
int out_if = wolfIP_forward_interface(s, if_idx, dest);
if (out_if >= 0) {
    if (ip->ttl <= 1) {
        wolfIP_send_ttl_exceeded(s, if_idx, ip);   /* ICMP type 11 to the source */
        return;
    }
    if (!wolfIP_forward_prepare(s, out_if, dest, mac, &broadcast)) {
        arp_queue_packet(s, out_if, dest, ip, len);  /* queue until ARP resolves */
        return;
    }
    ip->ttl--;
    ip->csum = 0;
    iphdr_set_checksum(ip);
    wolfIP_forward_packet(s, out_if, ip, len, broadcast ? NULL : mac, broadcast);
    return;
}
```

Key behaviors, all from `src/wolfip.c`:

- **TTL is decremented** by one on every forwarded packet, and the IP header
  checksum is recomputed.
- **TTL exhaustion** (`ttl <= 1`) produces an **ICMP TTL-exceeded** (type 11) back
  to the original source instead of forwarding.
- **Next-hop resolution** uses ARP on Ethernet out-interfaces; if the MAC is not
  yet known the packet is queued (`arp_queue_packet`) and sent once ARP resolves
  — it is not dropped.
- A **reverse-path (RPF) check** drops a packet whose source address is local to
  another of the host's interfaces before it is forwarded.
- Frames arriving on a non-loopback interface with a `127/8` source or
  destination are dropped (loopback addresses must not appear on the wire).

When forwarding is enabled, the optional static-route API is also compiled in
(`wolfip.h`): `wolfIP_route_add()`, `wolfIP_route_delete()`,
`wolfIP_route_lookup()`, `wolfIP_route_get()`, and `wolfIP_route_count()`. The
route lookup performs longest-prefix matching across connected subnets and static
routes together.

### Wiring a router

`src/test/test_wolfssl_forwarding.c` builds a two-interface router: interface 0
on the LAN, interface 1 on the WAN, each with its own IP config.

```c
/* router has WOLFIP_MAX_INTERFACES = 2, WOLFIP_ENABLE_FORWARDING = 1 */
wolfIP_init(router_stack);

tap_dev = wolfIP_getdev(router_stack);            /* iface 0 driver */
tap_init(tap_dev, TAP_IFNAME, host_addr.s_addr);

mem_link_attach(wolfIP_getdev_ex(router_stack, 1), /* iface 1 driver */ ...);

wolfIP_ipconfig_set_ex(router_stack, 0, router_lan_ip4, IP4(255,255,255,0), IP4(0,0,0,0));
wolfIP_ipconfig_set_ex(router_stack, 1, router_wan_ip4, IP4(255,255,255,0), IP4(0,0,0,0));
```

A host on the LAN reaching a server on the WAN sets the router's LAN address as
its gateway; the router forwards between the two connected subnets automatically.

If the next hop is **not** directly on one of those connected subnets, add a
static route:

```c
/* 10.20.0.0/16 is reachable via 192.168.1.254 on interface 0 */
wolfIP_route_add(s, 0, IP4(10,20,0,0), 16, IP4(192,168,1,254));
```

The static-route API is compiled only when forwarding is enabled:
`wolfIP_route_add()`, `wolfIP_route_delete()`, `wolfIP_route_lookup()`,
`wolfIP_route_get()`, and `wolfIP_route_count()`.

## 3. Multiple interfaces

`WOLFIP_MAX_INTERFACES` (default `2` in `config.h`) sizes the per-stack arrays of
link-layer descriptors and IP configurations. `wolfIP_init()` sets `if_count` to
`WOLFIP_MAX_INTERFACES` and initialises every slot (`src/wolfip.c`).

Each interface slot is addressed by a zero-based `if_idx`. There are two parallel
accessor families in `wolfip.h`:

| Legacy (first hardware iface) | Indexed (`_ex`) | Purpose |
|-------------------------------|-----------------|---------|
| `wolfIP_getdev(s)` | `wolfIP_getdev_ex(s, if_idx)` | Get the `struct wolfIP_ll_dev *` to wire to a driver. |
| `wolfIP_ipconfig_set(s, ip, mask, gw)` | `wolfIP_ipconfig_set_ex(s, if_idx, ip, mask, gw)` | Set IP / netmask / gateway. |
| `wolfIP_ipconfig_get(s, &ip, &mask, &gw)` | `wolfIP_ipconfig_get_ex(s, if_idx, &ip, &mask, &gw)` | Read IP config. |
| `wolfIP_recv(s, buf, len)` | `wolfIP_recv_ex(s, if_idx, buf, len)` | Hand an inbound frame to the stack. |

`wolfIP_getdev_ex()` returns `NULL` when `if_idx` is out of range. The legacy
helpers all target the **first hardware interface**, which is index `0` normally
but index `1` when loopback is enabled (see [section 4](#4-the-loopback-interface)
and the `WOLFIP_PRIMARY_IF_IDX` definition in `src/wolfip.c`).

### Configuring two interfaces

Wire each slot's `struct wolfIP_ll_dev` to a driver (set `mac`, `mtu`, and the
`poll`/`send` callbacks) and give each slot an IP config
(`src/test/test_wolfssl_forwarding.c`):

```c
wolfIP_init(s);

struct wolfIP_ll_dev *dev0 = wolfIP_getdev_ex(s, 0);
struct wolfIP_ll_dev *dev1 = wolfIP_getdev_ex(s, 1);
/* attach each dev to its driver: dev->poll, dev->send, dev->mac, dev->mtu ... */

wolfIP_ipconfig_set_ex(s, 0, IP4(192,168,1,1), IP4(255,255,255,0), IP4(0,0,0,0));
wolfIP_ipconfig_set_ex(s, 1, IP4(10,0,0,1),    IP4(255,255,255,0), IP4(0,0,0,0));
```

### Feeding received frames

`wolfIP_poll()` calls each interface's `poll` callback and routes the resulting
frame to the correct interface internally (`poll_devices`, `src/wolfip.c`) — so a
driver that implements `poll` needs no extra plumbing.

If instead you push frames into the stack yourself (for example from an ISR or a
bridge), tag each frame with the interface it arrived on using
`wolfIP_recv_ex()`:

```c
/* a frame arrived on interface 1 */
wolfIP_recv_ex(s, 1, frame_buf, frame_len);
```

`wolfIP_recv(s, ...)` is shorthand for `wolfIP_recv_ex(s, <primary iface>, ...)`,
so use the `_ex` form whenever more than one interface can deliver frames.

## 4. The loopback interface

Set `WOLFIP_ENABLE_LOOPBACK` to `1` (default `0`) to give the stack an internal
loopback interface. It **requires `WOLFIP_MAX_INTERFACES > 1`** — `config.h`
enforces this with a compile-time `#error`:

```c
#if WOLFIP_ENABLE_LOOPBACK && WOLFIP_MAX_INTERFACES < 2
#error "WOLFIP_ENABLE_LOOPBACK requires WOLFIP_MAX_INTERFACES > 1"
#endif
```

When enabled, `wolfIP_init()` configures **interface slot 0** as the loopback
device (`src/wolfip.c`):

- IP `127.0.0.1`, mask `255.0.0.0` (`WOLFIP_LOOPBACK_IP` / `WOLFIP_LOOPBACK_MASK`,
  i.e. `127.0.0.1/8`), gateway none.
- `ifname` `"lo"`, `non_ethernet = 1`, with internal `poll`/`send` callbacks that
  move frames through an in-memory queue (`wolfIP_loopback_poll` /
  `wolfIP_loopback_send`) — there is no driver to wire.

### The index shift

Enabling loopback claims index `0`, so the **first hardware interface shifts to
index `1`**. This is encoded by `WOLFIP_PRIMARY_IF_IDX` (`src/wolfip.c`):

```text
WOLFIP_ENABLE_LOOPBACK = 0          WOLFIP_ENABLE_LOOPBACK = 1
  idx 0 : first hardware iface        idx 0 : loopback (127.0.0.1/8)
  idx 1 : second hardware iface       idx 1 : first hardware iface
  ...                                 idx 2 : second hardware iface
                                      ...
WOLFIP_PRIMARY_IF_IDX = 0           WOLFIP_PRIMARY_IF_IDX = 1
```

The consequence for the **legacy accessors** is exact: `wolfIP_getdev()`,
`wolfIP_ipconfig_set()/_get()`, and `wolfIP_recv()` all operate on
`WOLFIP_PRIMARY_IF_IDX`, so with loopback enabled they act on your hardware NIC at
**index 1**, not index 0. To touch a specific slot regardless of build, use the
`_ex` accessors with an explicit index:

```c
/* loopback build: configure the real NIC explicitly at index 1 */
wolfIP_ipconfig_set_ex(s, 1, my_ip, my_mask, my_gw);
struct wolfIP_ll_dev *nic = wolfIP_getdev_ex(s, 1);   /* same as wolfIP_getdev() here */
```

### What works over 127.0.0.1

The loopback interface is a normal interface as far as the socket layer is
concerned: a socket bound to or connecting to `127.0.0.1` exchanges UDP datagrams
and TCP segments with another local socket through the in-memory loopback queue,
never touching hardware. Loopback addresses are confined to it — frames carrying a
`127/8` source or destination that arrive on a non-loopback interface are dropped
(`src/wolfip.c`). The queue depth is `WOLFIP_LOOPBACK_QUEUE_DEPTH` (default 4);
when it drains, blocked senders are woken via
`wolfIP_notify_loopback_space_available()`.

## 5. Troubleshooting

**`WOLFIP_IP_ADD_MEMBERSHIP` returns `-WOLFIP_EINVAL`.** Either the address is not
a multicast group, or you joined with `imr_interface = INADDR_ANY` before giving
the resolved interface a source IP. Call `wolfIP_ipconfig_set*()` first, then
join. Joining the same `{interface, group}` twice on one socket also returns
`-WOLFIP_EINVAL`.

**Joined but no multicast arrives.** Confirm the socket is bound to the
destination port and that you actually joined (an unjoined socket on the same port
gets nothing). On a real link, also confirm the upstream switch/router honors the
IGMPv3 report wolfIP sends on join.

**Multicast sends never reach the network.** The default multicast TTL is `1`,
which does not cross a router. Raise it with `WOLFIP_IP_MULTICAST_TTL`. If you
expect to read your own sends back, leave `WOLFIP_IP_MULTICAST_LOOP` enabled and
remember the loopback copy is delivered inside `wolfIP_poll()` after the wire
send — poll the stack before `recvfrom()`.

**Forwarding does nothing.** Check that `WOLFIP_ENABLE_FORWARDING = 1`, that
`WOLFIP_MAX_INTERFACES >= 2`, and that **both** interfaces have a configured,
non-zero IP — `wolfIP_forward_interface()` skips interfaces whose IP is
`IPADDR_ANY` and returns `-1` when `if_count < 2`.

**Forwarded traffic stops with ICMP "time exceeded".** The packet's TTL reached 1
at the router; this is expected behavior, not a bug. The originating host should
be using a TTL large enough for the hop count.

**Wrong interface after enabling loopback.** Remember the index shift: the legacy
accessors now target index 1 (the first NIC). Use `wolfIP_getdev_ex()` /
`wolfIP_ipconfig_set_ex()` with explicit indices to avoid ambiguity.

# wolfIP

## Description and project goals

wolfIP is a TCP/IP stack with no dynamic memory allocations, designed to be
used in resource-constrained embedded systems.

Endpoint only mode is supported, which means that wolfip can be used to
establish network connections but it does not route traffic between different
network interfaces.

A single network interface can be associated with the device.

## Features supported

- BSD-like, non blocking socket API, with custom callbacks
- No dynamic memory allocation
  - Fixed number of concurrent sockets
  - Pre-allocated buffers for packet processing in static memory

## Protocols and RFCs

| Layer | Protocol | Features | RFC(s) |
|-------|----------|----------|--------|
| **Data Link** | Ethernet II | Frame encapsulation | [IEEE 802.3](https://standards.ieee.org/ieee/802.3/10422/) |
| **Data Link** | ARP | Address resolution, request/reply | [RFC 826](https://datatracker.ietf.org/doc/html/rfc826) |
| **Network** | IPv4 | Datagram delivery, TTL handling | [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) |
| **Network** | IPv4 Forwarding | Multi-interface routing (optional) | [RFC 1812](https://datatracker.ietf.org/doc/html/rfc1812) |
| **Network** | ICMP | Echo request/reply, TTL exceeded | [RFC 792](https://datatracker.ietf.org/doc/html/rfc792) |
| **Network** | IPsec | ESP Transport mode | [RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303) |
| **Network** | WolfGuard | VPN tunnel via wolfguard kernel module (SECP256R1, AES-256-GCM, SHA-256) | See `wolf-sources/wolfssl/wolfguard/README.md` |
| **Transport** | UDP | Unicast datagrams, checksum | [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) |
| **Transport** | TCP | Connection management, reliable delivery | [RFC 793](https://datatracker.ietf.org/doc/html/rfc793), [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293) |
| **Transport** | TCP | Maximum Segment Size negotiation | [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) |
| **Transport** | TCP | TCP Timestamps, RTT measurement, PAWS, Window Scaling | [RFC 7323](https://datatracker.ietf.org/doc/html/rfc7323) |
| **Transport** | TCP | Retransmission timeout (RTO) computation | [RFC 6298](https://datatracker.ietf.org/doc/html/rfc6298), [RFC 5681](https://datatracker.ietf.org/doc/html/rfc5681) |
| **Transport** | TCP | TCP SACK | [RFC 2018](https://datatracker.ietf.org/doc/html/rfc2018), [RFC 2883](https://datatracker.ietf.org/doc/html/rfc2883), [RFC 6675](https://datatracker.ietf.org/doc/html/rfc6675) |
| **Transport** | TCP | Congestion Control: Slow start, congestion avoidance | [RFC 5681](https://datatracker.ietf.org/doc/html/rfc5681) |
| **Transport** | TCP | Fast Retransmit, triple duplicate ACK detection | [RFC 5681](https://datatracker.ietf.org/doc/html/rfc5681) |
| **Application** | DHCP | Client only (DORA) | [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131) |
| **Application** | DNS | A and PTR record queries (client) | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| **Application** | HTTP/HTTPS | Server with wolfSSL TLS support | [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110) |


## Functional tests with `LD_PRELOAD`

The POSIX shim builds `libwolfip.so`, which can be injected in front of
host tools so that calls to `socket(2)` and friends are redirected to the
wolfIP stack and the TAP device (`wtcp0`).  After running `make`:

```sh
sudo LD_PRELOAD=$PWD/libwolfip.so nc 10.10.10.2 80
```

The example above mirrors the existing `nc`-driven demos: any TCP sockets
opened by the intercepted process are serviced by wolfIP instead of the host
kernel.

### Ping over the TAP device

ICMP datagram sockets can be validated the same way.  With the TAP interface
created automatically by the shim and the host endpoint configured in
`config.h` (`HOST_STACK_IP` defaults to `10.10.10.1`), run:

```sh
sudo LD_PRELOAD=$PWD/libwolfip.so ping -I wtcp0 -c5 10.10.10.1
```

The `-I wtcp0` flag pins the test to the injected interface and `-c5`
generates five echo requests.  Successful replies confirm the ICMP
datagram socket support end-to-end through the tap device.

## WolfGuard support

wolfIP can use [WolfGuard](wolf-sources/wolfssl/wolfguard/README.md) as its
link-layer driver, giving every socket opened on the stack transparent
WireGuard-compatible encryption without any changes to application code.

### How it works

WolfGuard is a kernel module (`wolfguard.ko`) that registers a standard Linux
network interface (`ARPHRD_NONE`, identical in structure to the upstream
WireGuard driver) and performs the handshake and encryption inside the kernel
using wolfSSL's FIPS-ready primitives (SECP256R1, AES-256-GCM, SHA-256).

`wolfip_wolfguard.c` is a wolfIP ll_dev driver that bridges the two:

1. Creates the wolfguard interface via Netlink (`RTM_NEWLINK type=wolfguard`).
2. Configures keys and peers via the wolfguard Generic Netlink family
   (`WG_CMD_SET_DEVICE`).
3. Connects to the interface with an `AF_PACKET/SOCK_DGRAM` socket, injecting
   and receiving raw IP packets that the kernel module encrypts/decrypts
   transparently.
4. Provides a synthetic ARP proxy so wolfIP's Ethernet layer can resolve peer
   IPs without kernel ARP involvement.

### Prerequisites

Build and load the wolfguard kernel module and its wolfSSL dependency by
following the instructions in
[wolf-sources/wolfssl/wolfguard/README.md](wolf-sources/wolfssl/wolfguard/README.md).
Then load the modules before running any wolfguard-enabled binary:

```sh
insmod /lib/modules/$(uname -r)/wolfssl/libwolfssl.ko
insmod /path/to/wolfguard.ko
modprobe udp_tunnel
modprobe ip6_udp_tunnel
```

### Enabling wolfguard support

Add `-DWOLFIP_WOLFGUARD` to your `CFLAGS` and link `wolfip_wolfguard.c` into
your build. In the wolfIP Makefile the dedicated targets handle this
automatically:

```sh
make unit-wolfguard          # driver unit tests (no kernel module required)
make build/test-wolfguard    # functional test binary
```

To integrate into your own application, call `wolfIP_wg_init()` in place of
`tap_init()`:

```c
#include "wolfip_wolfguard.h"

struct wolfIP_wg_config cfg = { ... };  /* keys, peers, listen port */
struct wolfIP *stack;

wolfIP_init_static(&stack);
wolfIP_wg_init(&cfg, wolfIP_getdev(stack));
wolfIP_ipconfig_set(stack, atoip4("10.8.0.1"), atoip4("255.255.255.0"),
                   atoip4("10.8.0.1"));
/* use wolfIP sockets normally — all traffic is encrypted by wolfguard */
```

### Running the tests

**Unit tests** exercise the driver logic (ARP proxy, L2/L3 bridging) entirely
in userspace with a mock pipe — no kernel module required:

```sh
make unit-wolfguard
./build/test/unit-wolfguard
```

**Functional test** performs a full loopback: wolfIP sends a UDP packet,
wolfguard encrypts it, a kernel-side peer decrypts and echoes it back, and
wolfIP verifies the payload. Requires the kernel modules to be loaded,
`wg-fips` in `PATH`, and root (or `NET_ADMIN` capability) to create network
interfaces:

```sh
make build/test-wolfguard
sudo ./build/test-wolfguard
```

## FreeRTOS Port

wolfIP now includes a dedicated FreeRTOS wrapper port at:

- `src/port/freeRTOS/bsd_socket.c`
- `src/port/freeRTOS/bsd_socket.h`

This port follows the same model as the POSIX wrapper:

- One background task loops on `wolfIP_poll()`
- Socket wrappers serialize stack access with a mutex
- Blocking operations wait on callback-driven wakeups (instead of busy polling)

## Copyright and License

wolfIP is licensed under the GPLv3 license. See the LICENSE file for details.
Copyright (c) 2025 wolfSSL Inc.

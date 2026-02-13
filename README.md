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
| **Transport** | UDP | Unicast datagrams, checksum | [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) |
| **Transport** | TCP | Connection management, reliable delivery | [RFC 793](https://datatracker.ietf.org/doc/html/rfc793), [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293) |
| **Transport** | TCP | Maximum Segment Size negotiation | [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) |
| **Transport** | TCP | TCP Timestamps, RTT measurement, PAWS, Window Scaling | [RFC 7323](https://datatracker.ietf.org/doc/html/rfc7323) |
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

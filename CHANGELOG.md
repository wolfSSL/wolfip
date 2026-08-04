# Changelog

## v1.0 2026-03-31

Initial public wolfIP release.

- Zero-allocation IPv4 stack with static buffers, fixed socket tables, and a BSD-like non-blocking socket API with callback support.
- Core protocol support for Ethernet II, ARP, IPv4, ICMP, UDP, TCP, DHCP client, and DNS client.
- TCP support for MSS, timestamps, PAWS, window scaling, RTO, SACK, slow start, congestion avoidance, and fast retransmit.
- HTTP/HTTPS server support.
- IPsec ESP transport mode support.
- IP filtering support, including wolfSentry integration.
- Native wolfGuard support.
- Optional IPv4 forwarding for multi-interface builds.
- Integration layers for wolfSSL, wolfSSH, wolfMQTT, FreeRTOS blocking BSD sockets, and POSIX `LD_PRELOAD` socket interception via `libwolfip.so`.
- Host link drivers for Linux TAP/TUN, Darwin utun, FreeBSD TAP, and VDE2.
- Embedded ports for STM32H753ZI, STM32H563, STM32N6, VA416xx, and Raspberry Pi Pico USB networking demos.
- Shared Ethernet support for STM32 and VA416xx targets, plus common embedded service glue and certificates under `src/port`.

## Unreleased

- IPv6 groundwork (`WOLFIP_IPV6`, off by default): the `ip6` address type with scope/type predicates, prefix operations and RFC 5952 text conversion; IPv6 header encapsulation and parsing with the RFC 8200 40-byte pseudo-header checksum; ethertype and multicast MAC demux. Upper-layer delivery, ICMPv6, Neighbor Discovery, SLAAC and DHCPv6 are not implemented yet.
- New `WOLFIP_IF_MULTICONF` feature (off by default): several addresses per interface, via `wolfIP_ifaddr_add4()` / `add6()` / `del4()` / `del6()` / `count()` / `get()` / `is_local4()`. Required by IPv6, and independently useful for IPv4 aliasing. `struct ipconf` still holds the primary IPv4 address of each interface, so every existing caller is unaffected and the default build does not grow.
- Declared the integration surface for a third-party DLR implementation: `wolfIP_register_l2_handler()` and `struct wolfIP_switch_ops`. See `docs/dlr_integration.md`.

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

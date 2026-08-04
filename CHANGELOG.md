# Changelog

## v1.1.0 2026-10-02

- New ports: AMD/Xilinx (ZCU102, Versal VMK180, Zynq-7000), NXP QorIQ (FMan, ENETC, eTSEC, QUICC UCC), PIC32MZ, RealTek AmebaPro2, NXP LPC54S018M, STM32C5A3, STM32F437/F439, Pico 2 W, Zephyr; wolfHAL as a submodule under `lib/`; big-endian host support.
- TFTP client and server.
- Multicast UDP sockets with IGMP.
- Raw and AF_PACKET sockets.
- VLAN 802.1Q tagging and filtering.
- Multi-interface routing and forwarding: static route table, martian and strict-RPF source checks.
- Loopback interface.
- wolfSupplicant: clean-room WPA/WPA2/WPA3 supplicant with WPA3-SAE interop; wired 802.1X EAP-TLS demo on STM32H563.
- MACsec 802.1AE (SecY) with wolfMKA control plane.
- wolfGuard: key rotation, cookie expiry, source policy enforcement.
- TCP: RFC 9293 acceptability and RST handling, pre-accept and late-accept fixes, PAWS in TIME_WAIT/LAST_ACK, MSS floor, 64 s RTO cap, retransmit in teardown states.
- DHCP: RFC 4331 DAD before lease bind, exponential retransmit backoff, jittered T1/T2, server-ID validation.
- DNS response validation per RFC 1035; IGMP query responses deferred per RFC 3376.
- Security hardening: ARP guardrails (DAD, anti-poisoning, rate limiting), IPsec ESP replay window and SA persistence, TFTP and HTTP hardening, raw socket receive enforcement.
- New APIs: wolfIP_sock_abort(), IP_TOS setsockopt, SO_RCVTIMEO; FreeRTOS ISR-safe wake and deadline-based sleep.
- Compile-out options for the DHCP client and zero-UDP builds.
- Docs: porting guide, how-to guides (TLS, HTTP, wolfGuard, DHCP/DNS, IPsec ESP, TFTP, advanced IPv4), lwIP migration guide with Japanese translation, CONTRIBUTING.md.
- wolfIP_poll refactor
- Fixed ESP anti-replay window issue (CWE-354). Reported by: Matan Radomski.

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

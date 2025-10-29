# wolfIP

## Description and project goals

wolfIP is a TCP/IP stack with no dynamic memory allocations, designed to be
used in resource-constrained embedded systems.

Endpoint only mode is supported, which means that wolfip can be used to
establish network connections but it does not route traffic between different
network interfaces.

A single network interface can be associated with the device.

## Features supported

- ARP (RFC 826)
- IPv4 (RFC 791)
- ICMP (RFC 792): only ping replies
- DHCP (RFC 2131): client only
- DNS  (RFC 1035): client only
- UDP (RFC 768): unicast only
- TCP (RFC 793)
  - TCP options supported: Timestamps, Maximum Segment Size
- BSD-like, non blocking socket API, with custom callbacks
- No dynamic memory allocation
  - Fixed number of concurrent sockets
  - Pre-allocated buffers for packet processing in static memory


## Copyright and License

wolfIP is licensed under the GPLv3 license. See the LICENSE file for details.
Copyright (c) 2025 wolfSSL Inc.


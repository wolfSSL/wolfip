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

## Copyright and License

wolfIP is licensed under the GPLv3 license. See the LICENSE file for details.
Copyright (c) 2025 wolfSSL Inc.

# wolfIP API Documentation

## Overview

wolfIP is a minimal TCP/IP stack designed for resource-constrained embedded systems. It features zero dynamic memory allocation, using pre-allocated buffers and a fixed number of concurrent sockets.

## Key Features

- No dynamic memory allocation
- Fixed number of concurrent sockets
- Pre-allocated buffers for packet processing
- BSD-like non-blocking socket API with callbacks
- Protocol Support:
  - ARP (RFC 826)
  - IPv4 (RFC 791)
  - ICMP (RFC 792) - ping replies only
  - DHCP (RFC 2131) - client only
  - DNS (RFC 1035) - client only
  - UDP (RFC 768) - unicast only
  - TCP (RFC 793) with options (Timestamps, MSS)

## Core Data Structures

### Device Driver Interface
```c
struct ll {
    uint8_t mac[6];          // Device MAC address
    char ifname[16];         // Interface name
    int (*poll)(struct ll *ll, void *buf, uint32_t len);  // Receive function
    int (*send)(struct ll *ll, void *buf, uint32_t len);  // Transmit function
};
```
wolfIP maintains an array of these descriptors sized by `WOLFIP_MAX_INTERFACES` (default `1`). Call `wolfIP_getdev_ex()` to access a specific slot; the legacy `wolfIP_getdev()` helper targets the first hardware slot (index `0` normally, or `1` when the optional loopback interface is enabled).

### IP Configuration
```c
struct ipconf {
    struct ll *ll;           // Link layer device
    ip4 ip;                  // IPv4 address
    ip4 mask;                // Subnet mask
    ip4 gw;                  // Default gateway
};
```
Each `struct wolfIP` instance owns `WOLFIP_MAX_INTERFACES` `ipconf` entries—one per link-layer slot. Use the `_ex` helpers to read or update a specific interface; the legacy accessors operate on the first hardware interface (index `0` unless loopback support is compiled in).

If `WOLFIP_ENABLE_FORWARDING` is set to `1` at compile time, the stack performs simple IPv4 forwarding between interfaces. Packets received on one interface whose destinations match another configured interface are re-sent with the IP TTL decreased by one (or an ICMP TTL-exceeded response if the TTL would drop to zero).

Enabling `WOLFIP_ENABLE_LOOPBACK` (requires `WOLFIP_MAX_INTERFACES > 1`) creates an internal loopback
device at index `0` with the fixed address `127.0.0.1/8`. Traffic sent to that address is reflected back
through the stack so local sockets, pings, and other services behave as they would on a standard
loopback interface; the first hardware interface then shifts to index `1` for legacy helpers.

### Socket Address Structures
```c
struct wolfIP_sockaddr_in {
    uint16_t sin_family;     // Address family (AF_INET)
    uint16_t sin_port;       // Port number
    struct sin_addr {
        uint32_t s_addr;     // IPv4 address
    } sin_addr;
};

struct wolfIP_sockaddr {
    uint16_t sa_family;      // Address family
};
```

## Socket Interface Functions

### Socket Creation and Control
```c
int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
```
Creates a new socket.
- Parameters:
  - s: wolfIP instance
  - domain: Address family (AF_INET)
  - type: Socket type (SOCK_STREAM/SOCK_DGRAM)
  - protocol: Protocol (usually 0)
- Returns: Socket descriptor or negative error code

```c
int wolfIP_sock_bind(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
```
Binds a socket to a local address.
- Parameters:
  - s: wolfIP instance
  - sockfd: Socket descriptor
  - addr: Local address to bind to
  - addrlen: Length of address structure
- Returns: 0 on success, negative error code on failure

```c
int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog);
```
Marks a socket as passive (listening for connections).
- Parameters:
  - s: wolfIP instance
  - sockfd: Socket descriptor
  - backlog: Maximum length of pending connections queue
- Returns: 0 on success, negative error code on failure

### Connection Management
```c
int wolfIP_sock_connect(struct wolfIP *s, int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
```
Initiates a connection on a socket.
- Parameters:
  - s: wolfIP instance
  - sockfd: Socket descriptor
  - addr: Address to connect to
  - addrlen: Length of address structure
- Returns: 0 on success, negative error code on failure

```c
int wolfIP_sock_accept(struct wolfIP *s, int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);
```
Accepts a connection on a listening socket.
- Parameters:
  - s: wolfIP instance
  - sockfd: Listening socket descriptor
  - addr: Address of connecting peer
  - addrlen: Length of address structure
- Returns: New socket descriptor or negative error code

### Data Transfer
```c
int wolfIP_sock_send(struct wolfIP *s, int sockfd, const void *buf, size_t len, int flags);
int wolfIP_sock_recv(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags);
```
Send/receive data on a connected socket.
- Parameters:
  - s: wolfIP instance
  - sockfd: Socket descriptor
  - buf: Data buffer
  - len: Buffer length
  - flags: Operation flags
- Returns: Number of bytes transferred or negative error code

```c
int wolfIP_sock_sendto(struct wolfIP *s, int sockfd, const void *buf, size_t len, int flags, const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen);
int wolfIP_sock_recvfrom(struct wolfIP *s, int sockfd, void *buf, size_t len, int flags, struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);
```
Send/receive data on a datagram socket.
- Parameters similar to send/recv with additional address parameters

## Stack Interface Functions

```c
void wolfIP_init(struct wolfIP *s);
```
Initializes the TCP/IP stack.
- Parameters:
  - s: wolfIP instance to initialize

```c
void wolfIP_init_static(struct wolfIP **s);
```
Initializes a static wolfIP instance.
- Parameters:
  - s: Pointer to wolfIP instance pointer

```c
size_t wolfIP_instance_size(void);
```
Returns the size (in bytes) required to store a `struct wolfIP`. Use this when allocating stacks from custom memory managers.

```c
int wolfIP_poll(struct wolfIP *s, uint64_t now);
```
Processes pending network events.
- Parameters:
  - s: wolfIP instance
  - now: Current timestamp
- Returns: Number of events processed

```c
void wolfIP_recv(struct wolfIP *s, void *buf, uint32_t len);
void wolfIP_recv_ex(struct wolfIP *s, unsigned int if_idx, void *buf, uint32_t len);
```
Pass inbound frames to the stack. `_ex` allows the caller to specify which interface slot produced the frame.

```c
void wolfIP_ipconfig_set(struct wolfIP *s, ip4 ip, ip4 mask, ip4 gw);
void wolfIP_ipconfig_get(struct wolfIP *s, ip4 *ip, ip4 *mask, ip4 *gw);
```
Set/get IP configuration.
- Parameters:
  - s: wolfIP instance
  - ip: IPv4 address
  - mask: Subnet mask
  - gw: Default gateway

```c
void wolfIP_ipconfig_set_ex(struct wolfIP *s, unsigned int if_idx, ip4 ip, ip4 mask, ip4 gw);
void wolfIP_ipconfig_get_ex(struct wolfIP *s, unsigned int if_idx, ip4 *ip, ip4 *mask, ip4 *gw);
```
Per-interface versions of the IP configuration helpers. The legacy functions target interface `0`.

```c
struct ll *wolfIP_getdev(struct wolfIP *s);
struct ll *wolfIP_getdev_ex(struct wolfIP *s, unsigned int if_idx);
```
Access the link-layer descriptor(s) that should be wired to hardware drivers. `_ex` returns `NULL` if `if_idx` exceeds `WOLFIP_MAX_INTERFACES`.

## DHCP Client Functions

```c
int dhcp_client_init(struct wolfIP *s);
```
Initializes DHCP client.
- Parameters:
  - s: wolfIP instance
- Returns: 0 on success, negative error code on failure

```c
int dhcp_bound(struct wolfIP *s);
```
Checks if DHCP client is bound.
- Parameters:
  - s: wolfIP instance
- Returns: 1 if bound, 0 otherwise

## DNS Client Functions

```c
int nslookup(struct wolfIP *s, const char *name, uint16_t *id, void (*lookup_cb)(uint32_t ip));
```
Performs DNS lookup.
- Parameters:
  - s: wolfIP instance
  - name: Hostname to resolve
  - id: Transaction ID
  - lookup_cb: Callback function for result
- Returns: 0 on success, negative error code on failure

## Utility Functions

```c
uint32_t atou(const char *s);
```
Converts ASCII string to unsigned integer.

```c
ip4 atoip4(const char *ip);
```
Converts dotted decimal IP address string to 32-bit integer.

```c
void iptoa(ip4 ip, char *buf);
```
Converts 32-bit IP address to dotted decimal string.

## Event Callback Registration

```c
void wolfIP_register_callback(struct wolfIP *s, int sock_fd, void (*cb)(int sock_fd, uint16_t events, void *arg), void *arg);
```
Registers event callback for a socket.
- Parameters:
  - s: wolfIP instance
  - sock_fd: Socket descriptor
  - cb: Callback function
  - arg: User data for callback

Event flags:
- CB_EVENT_READABLE (0x01): Data available or connection accepted
- CB_EVENT_TIMEOUT (0x02): Operation timed out
- CB_EVENT_WRITABLE (0x04): Connected or space available to send
- CB_EVENT_CLOSED (0x10): Connection closed by peer

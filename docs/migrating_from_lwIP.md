# Migrating from lwIP to wolfIP

## Table of Contents

- [1. Scope](#1-scope)
- [2. Mental model: lwIP versus wolfIP](#2-mental-model-lwip-versus-wolfip)
- [3. Configuration migration: from `lwipopts.h` to wolfIP `config.h`](#3-configuration-migration-from-lwipoptsh-to-wolfip-configh)
- [4. Initialization and network-device wiring](#4-initialization-and-network-device-wiring)
- [5. Porting existing lwIP network drivers](#5-porting-existing-lwip-network-drivers)
- [6. Wiring a random-number source](#6-wiring-a-random-number-source)
- [7. Bare-metal socket API migration](#7-bare-metal-socket-api-migration)
- [8. Translating a simple TCP server from lwIP raw/classic API](#8-translating-a-simple-tcp-server-from-lwip-rawclassic-api)
- [9. Translating a simple TCP server from lwIP ALTCP interfaces](#9-translating-a-simple-tcp-server-from-lwip-altcp-interfaces)
- [10. RTOS integration](#10-rtos-integration)
- [11. Porting wolfIP to a new RTOS](#11-porting-wolfip-to-a-new-rtos)
- [12. Migration checklist](#12-migration-checklist)
- [13. Common migration pitfalls](#13-common-migration-pitfalls)
- [14. Quick API mapping](#14-quick-api-mapping)

## 1. Scope

This guide is for developers and integrators moving embedded networking code from lwIP to wolfIP. It focuses on:

- the design difference between lwIP and wolfIP;
- replacing `lwipopts.h` configuration with wolfIP `config.h`;
- wiring a random-number source;
- porting existing lwIP Ethernet/network drivers;
- migrating bare-metal TCP server code from lwIP raw/classic and lwIP ALTCP-style APIs;
- integrating wolfIP into an RTOS, using the existing FreeRTOS BSD-socket wrapper as the model.

The examples are intentionally small. They are meant to show migration patterns, not production error handling, resource accounting, or board-specific Ethernet driver code.

---

## 2. Mental model: lwIP versus wolfIP

### 2.1 lwIP model

lwIP is highly configurable. A typical lwIP application chooses among raw callbacks, Netconn, and BSD sockets, then configures memory pools, pbuf pools, protocol control blocks, mailbox/thread support, TCP/IP-thread behavior, and protocol features through `lwipopts.h`.

For example, lwIP exposes separate pool counts for raw PCBs, UDP PCBs, active TCP PCBs, listening TCP PCBs, queued TCP segments, Netconn objects, API messages, DNS API messages, socket/select helpers, pbuf pools, ARP queue entries, and timeouts. The official lwIP options documentation lists these as independent knobs such as `MEMP_NUM_TCP_PCB`, `MEMP_NUM_TCP_PCB_LISTEN`, `MEMP_NUM_UDP_PCB`, `MEMP_NUM_TCP_SEG`, `MEMP_NUM_NETCONN`, `MEMP_NUM_TCPIP_MSG_API`, and `PBUF_POOL_SIZE`.

### 2.2 wolfIP model

wolfIP is more direct and more static. The stack instance owns fixed arrays of sockets and fixed-size buffers. The current `struct wolfIP` contains arrays such as:

- `tcpsockets[MAX_TCPSOCKETS]`
- `udpsockets[MAX_UDPSOCKETS]`
- `icmpsockets[MAX_ICMPSOCKETS]`
- optional raw and packet socket arrays when those features are enabled

The default `config.h` sets `MAX_TCPSOCKETS` to 4, `MAX_UDPSOCKETS` to 2, `MAX_ICMPSOCKETS` to 2, `RXBUF_SIZE` to 20 KiB, and `TXBUF_SIZE` to 32 KiB. It also sets defaults for MTU, neighbors, interfaces, loopback, raw sockets, packet sockets, forwarding, and static DNS.

The practical implication is that migration is not “find every lwIP pool and copy the number.” Instead, decide the maximum number of concurrently live TCP, UDP, ICMP, raw, and packet sockets your product needs, then size the RX/TX buffers and MTU around the traffic pattern.

### 2.3 Sockets are finite per type

wolfIP socket descriptors encode both socket type and socket index. The public header defines socket marks such as `MARK_TCP_SOCKET`, `MARK_UDP_SOCKET`, `MARK_ICMP_SOCKET`, `MARK_RAW_SOCKET`, and `MARK_PACKET_SOCKET`, plus helpers like `IS_SOCKET_TCP(fd)` and `SOCKET_UNMARK(fd)`. The header also enforces that each socket count must fit under 256, because the low byte is used as the socket index.

This matters during migration:

- a listening TCP socket consumes a TCP socket slot;
- each accepted TCP connection consumes another TCP socket slot;
- UDP sockets consume from the UDP socket pool;
- DNS and DHCP may also consume sockets internally depending on how you use them;
- increasing backlog does not create an unbounded accept queue.

For a simple TCP server that allows one listener plus three simultaneous clients, `MAX_TCPSOCKETS 4` is the minimum. If the product must accept one listener plus eight clients, set `MAX_TCPSOCKETS` to at least 9.

---

## 3. Configuration migration: from `lwipopts.h` to wolfIP `config.h`

### 3.1 What changes conceptually

In lwIP, `lwipopts.h` is both a feature-selection file and a resource-pool tuning file. You may have options for:

- OS mode: `NO_SYS`, `SYS_LIGHTWEIGHT_PROT`, `LWIP_NETCONN`, `LWIP_SOCKET`;
- memory: `MEM_SIZE`, `MEMP_NUM_*`, `PBUF_POOL_SIZE`, `PBUF_POOL_BUFSIZE`;
- TCP: `TCP_MSS`, `TCP_WND`, `TCP_SND_BUF`, `TCP_SND_QUEUELEN`, `MEMP_NUM_TCP_SEG`;
- protocols: `LWIP_TCP`, `LWIP_UDP`, `LWIP_ICMP`, `LWIP_DHCP`, `LWIP_DNS`, `LWIP_IPV4`, `LWIP_IPV6`;
- API mode: raw, Netconn, sockets, ALTCP;
- port-specific system settings.

In wolfIP, start from `config.h` and keep it short. The important resource knobs are direct: number of sockets per type, buffer sizes, MTU, neighbor count, interface count, and optional features such as raw sockets, packet sockets, forwarding, loopback, and HTTP support.

### 3.2 Recommended migration table

| lwIP configuration area | Typical lwIP option | wolfIP migration decision |
|---|---:|---|
| Active TCP PCBs | `MEMP_NUM_TCP_PCB` | Use `MAX_TCPSOCKETS`. Count listeners and accepted/client sockets together. |
| TCP listen PCBs | `MEMP_NUM_TCP_PCB_LISTEN` | No separate wolfIP listener pool. A listening server uses one TCP socket slot. |
| UDP PCBs | `MEMP_NUM_UDP_PCB` | Use `MAX_UDPSOCKETS`. Include application UDP sockets and any internal users you enable. |
| ICMP/raw handling | `LWIP_RAW`, `MEMP_NUM_RAW_PCB` | Use `MAX_ICMPSOCKETS` for ICMP sockets. Enable `WOLFIP_RAWSOCKETS` and set `WOLFIP_MAX_RAWSOCKETS` only when raw sockets are needed. |
| Packet sockets | usually port/platform specific | Enable `WOLFIP_PACKET_SOCKETS` and size `WOLFIP_MAX_PACKETSOCKETS` only when Ethernet packet sockets are needed. |
| pbuf pool | `PBUF_POOL_SIZE`, `PBUF_POOL_BUFSIZE` | Size `RXBUF_SIZE`, `TXBUF_SIZE`, and `LINK_MTU`. |
| TCP segment queue | `MEMP_NUM_TCP_SEG`, `TCP_SND_QUEUELEN` | Size `TXBUF_SIZE` and TCP socket count. wolfIP queues into its fixed TX memory. |
| TCP window/send buffer | `TCP_WND`, `TCP_SND_BUF` | Review wolfIP TCP buffer behavior and increase `RXBUF_SIZE`/`TXBUF_SIZE` if application throughput stalls. |
| ARP neighbor cache | `ARP_TABLE_SIZE`, `MEMP_NUM_ARP_QUEUE` | Use `MAX_NEIGHBORS`; wolfIP also has ARP pending request storage. |
| Interfaces | `LWIP_SINGLE_NETIF`, `netif` setup | Use `WOLFIP_MAX_INTERFACES` and `wolfIP_getdev_ex()` / `wolfIP_ipconfig_set_ex()` for multiple interfaces. |
| IPv6 | `LWIP_IPV6` | Do not assume a direct config mapping. Migrate only IPv4 code unless your wolfIP version/fork explicitly supports the needed IPv6 paths. |
| Netconn/BSD sockets | `LWIP_NETCONN`, `LWIP_SOCKET` | Bare metal uses `wolfIP_sock_*` directly. RTOS ports can add BSD-style wrappers around `wolfIP_sock_*`. |
| ALTCP/TLS | `LWIP_ALTCP`, `LWIP_ALTCP_TLS` | Replace ALTCP transport callbacks with wolfIP sockets. For TLS, place wolfSSL above the wolfIP socket and use the wolfIP/wolfSSL integration hooks when enabled. |
| Static IP | `IP_ADDR`, `NETMASK`, `GW` or board config | Use `wolfIP_ipconfig_set()` or `wolfIP_ipconfig_set_ex()`. |
| Static DNS | port-specific | Use `WOLFIP_STATIC_DNS_IP` or set DNS state through the stack APIs available in your version. |

### 3.3 Minimal `config.h` starting point

```c
#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#define ETHERNET

#define LINK_MTU 1536
#ifndef LINK_MTU_MIN
#define LINK_MTU_MIN 64U
#endif

#define MAX_TCPSOCKETS  5  /* 1 listener + 4 clients */
#define MAX_UDPSOCKETS  2
#define MAX_ICMPSOCKETS 1

#define RXBUF_SIZE (20 * 1024)
#define TXBUF_SIZE (32 * 1024)

#define MAX_NEIGHBORS 16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 1
#endif

#ifndef WOLFIP_RAWSOCKETS
#define WOLFIP_RAWSOCKETS 0
#endif

#ifndef WOLFIP_PACKET_SOCKETS
#define WOLFIP_PACKET_SOCKETS 0
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

#ifndef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK 0
#endif

#define WOLFIP_STATIC_DNS_IP "9.9.9.9"

#endif
```

For a server, do not forget to include the listening socket in `MAX_TCPSOCKETS`. For example, a server with one listener and four clients needs at least five TCP sockets.

---

## 4. Initialization and network-device wiring

wolfIP exposes a small link-layer driver interface:

```c
struct wolfIP_ll_dev {
    uint8_t mac[6];
    char ifname[16];
    uint8_t non_ethernet;
    uint32_t mtu;

    int (*poll)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    int (*send)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);

    void *priv;
};
```

The stack can be initialized with `wolfIP_init()` on caller-provided storage, or with `wolfIP_init_static()` when static stack storage is enabled. `wolfIP_instance_size()` returns the stack object size. The static initializer is disabled if `WOLFIP_NOSTATIC` is defined.

A typical bare-metal setup is:

```c
#include "config.h"
#include "wolfip.h"

static struct wolfIP *ipstack;

static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /*
     * Return:
     *   >0 number of bytes received
     *    0 no packet available
     *   <0 driver error
     */
    return board_eth_poll(ll->priv, buf, len);
}

static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /*
     * Return:
     *    0 or positive on success
     *   -WOLFIP_EAGAIN if the driver cannot accept the frame yet
     *   negative on hard error
     */
    return board_eth_send(ll->priv, buf, len);
}

void network_init(void)
{
    struct wolfIP_ll_dev *dev;

    wolfIP_init_static(&ipstack);

    dev = wolfIP_getdev(ipstack);
    dev->priv = board_eth_context();
    dev->poll = eth_poll;
    dev->send = eth_send;
    dev->mtu = LINK_MTU;
    dev->mac[0] = 0x02;
    dev->mac[1] = 0x00;
    dev->mac[2] = 0x00;
    dev->mac[3] = 0x00;
    dev->mac[4] = 0x00;
    dev->mac[5] = 0x01;

    wolfIP_ipconfig_set(
        ipstack,
        atoip4("192.168.1.50"),
        atoip4("255.255.255.0"),
        atoip4("192.168.1.1")
    );
}

void network_poll_forever(void)
{
    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

`wolfIP_poll()` is the core progress function. It polls each configured link-layer device, processes received packets, runs timers, dispatches socket callbacks, and attempts to transmit pending TCP/UDP/ICMP/raw/packet data.

---


## 5. Porting existing lwIP network drivers

### 5.1 What changes at the driver boundary

An lwIP Ethernet driver normally sits behind `struct netif`. The driver initialization callback fills fields such as MAC address, MTU, interface flags, `netif->state`, `netif->output`, and `netif->linkoutput`. Transmit usually receives a `struct pbuf *` chain from `netif->linkoutput`; receive usually allocates a `PBUF_RAW` pbuf or pbuf chain, copies the incoming frame into it, and passes it upward through `netif->input(p, netif)`.

wolfIP removes that `netif`/`pbuf` boundary. The driver exposes one `struct wolfIP_ll_dev` per interface. The stack calls the driver's `poll` function from `wolfIP_poll()` to ask for one complete received frame, and calls the driver's `send` function when it has one complete frame ready for the hardware. The stack buffer passed to `poll` or `send` is linear; the driver does not receive or return a pbuf chain.

Use this mental mapping:

| lwIP driver concept | wolfIP driver concept |
|---|---|
| `struct netif` | `struct wolfIP_ll_dev` plus `ll->priv` for driver state |
| `netif->state` | `ll->priv` |
| `netif->hwaddr[]` | `ll->mac[]` |
| `netif->mtu` | `ll->mtu` or `wolfIP_mtu_set()`; for Ethernet this is the wolfIP frame budget, with the IPv4 payload MTU derived after link overhead |
| `netif->linkoutput(netif, pbuf)` | `ll->send(ll, frame, len)` |
| `low_level_input()` allocating `pbuf` | `ll->poll(ll, buf, len)` copying into wolfIP's buffer |
| `netif->input(p, netif)` | not called by the driver; wolfIP calls its receive path after `poll` returns a frame |
| `pbuf` chain traversal | not needed; wolfIP passes a single contiguous frame buffer |
| `netif_add()` / `netif_set_default()` | `wolfIP_getdev()` / `wolfIP_getdev_ex()` and `wolfIP_ipconfig_set()` / `wolfIP_ipconfig_set_ex()` |

### 5.2 Typical lwIP pbuf-based Ethernet port

The following is a made-up but representative lwIP Ethernet driver. It is intentionally small: the hardware functions are placeholders for your DMA descriptor or MAC driver.

```c
#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

struct my_lwip_eth {
    void *hw;
    uint8_t mac[6];
};

static err_t my_low_level_output(struct netif *netif, struct pbuf *p)
{
    struct my_lwip_eth *eth = (struct my_lwip_eth *)netif->state;
    struct pbuf *q;

    /* p can be a chain. The driver must transmit all fragments as one frame. */
    if (my_hw_tx_begin(eth->hw, p->tot_len) != 0) {
        return ERR_IF;
    }

    for (q = p; q != NULL; q = q->next) {
        if (my_hw_tx_write(eth->hw, q->payload, q->len) != 0) {
            my_hw_tx_abort(eth->hw);
            return ERR_IF;
        }
    }

    if (my_hw_tx_commit(eth->hw) != 0) {
        return ERR_IF;
    }

    return ERR_OK;
}

static struct pbuf *my_low_level_input(struct netif *netif)
{
    struct my_lwip_eth *eth = (struct my_lwip_eth *)netif->state;
    struct pbuf *p;
    struct pbuf *q;
    uint16_t frame_len;

    if (!my_hw_rx_ready(eth->hw)) {
        return NULL;
    }

    frame_len = my_hw_rx_frame_len(eth->hw);
    p = pbuf_alloc(PBUF_RAW, frame_len, PBUF_POOL);
    if (p == NULL) {
        my_hw_rx_drop(eth->hw);
        return NULL;
    }

    /* The incoming Ethernet frame is copied into the pbuf chain. */
    for (q = p; q != NULL; q = q->next) {
        if (my_hw_rx_read(eth->hw, q->payload, q->len) != 0) {
            pbuf_free(p);
            my_hw_rx_drop(eth->hw);
            return NULL;
        }
    }

    my_hw_rx_release(eth->hw);
    return p;
}

void my_ethernetif_input(struct netif *netif)
{
    struct pbuf *p = my_low_level_input(netif);

    if (p == NULL) {
        return;
    }

    if (netif->input(p, netif) != ERR_OK) {
        pbuf_free(p);
    }
}

err_t my_ethernetif_init(struct netif *netif)
{
    static struct my_lwip_eth eth0;

    eth0.hw = my_hw_open(0);
    my_hw_get_mac(eth0.hw, eth0.mac);

    netif->state = &eth0;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    memcpy(netif->hwaddr, eth0.mac, sizeof(eth0.mac));
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    netif->output = etharp_output;
    netif->linkoutput = my_low_level_output;

    return ERR_OK;
}
```

The important lwIP details to preserve when translating are:

* transmit receives one logical Ethernet frame, but the bytes may be split across a pbuf chain;
* receive creates pbuf storage before handing the packet to lwIP;
* the driver often has a separate `ethernetif_input()` path that must be called from a main loop, interrupt bottom-half, or RTOS task.

### 5.3 Equivalent wolfIP driver using `send` and `poll`

In wolfIP, make the hardware driver copy one full frame into or out of the linear buffer supplied by the stack. Do not keep the `buf` pointer after `send` or `poll` returns unless your hardware integration guarantees the memory remains valid, which a portable driver should not assume.

```c
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"

struct my_wolfip_eth {
    void *hw;
    uint8_t mac[6];
};

static int my_wolfip_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct my_wolfip_eth *eth = (struct my_wolfip_eth *)ll->priv;
    uint32_t frame_len;

    if (!my_hw_rx_ready(eth->hw)) {
        return 0; /* No frame available now. */
    }

    frame_len = my_hw_rx_frame_len(eth->hw);
    if (frame_len > len) {
        my_hw_rx_drop(eth->hw);
        return -WOLFIP_EINVAL;
    }

    if (my_hw_rx_read_frame(eth->hw, buf, frame_len) != 0) {
        my_hw_rx_drop(eth->hw);
        return -WOLFIP_EINVAL;
    }

    my_hw_rx_release(eth->hw);
    return (int)frame_len; /* One complete Ethernet frame, including header. */
}

static int my_wolfip_eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct my_wolfip_eth *eth = (struct my_wolfip_eth *)ll->priv;

    if (len > LINK_MTU) {
        return -WOLFIP_EINVAL;
    }

    if (!my_hw_tx_has_free_desc(eth->hw)) {
        return -WOLFIP_EAGAIN;
    }

    /* The wolfIP buffer is linear. Queue or copy it into hardware-owned memory. */
    if (my_hw_tx_enqueue_copy(eth->hw, buf, len) != 0) {
        return -WOLFIP_EAGAIN;
    }

    return 0;
}
```

The receive path is inverted compared with the lwIP version. You no longer allocate a pbuf and call `netif->input()`. Instead, `wolfIP_poll()` calls `my_wolfip_eth_poll()`. If `poll` returns a positive frame length, wolfIP processes the frame internally. If it returns `0`, there was no packet to process. If it returns a negative value, the stack does not process a frame for that poll attempt.

The transmit path is also simpler at the stack boundary. You no longer walk a pbuf chain. wolfIP passes a contiguous Ethernet frame to `send`. A return value of `0` means the driver accepted the frame. `-WOLFIP_EAGAIN` means the TX ring or hardware queue is temporarily full and the stack should try again on a later `wolfIP_poll()` cycle.

### 5.4 Initializing wolfIP interfaces

For one physical Ethernet interface, initialize the stack, retrieve the primary link-layer device, fill the driver callbacks and metadata, then set the IPv4 configuration. In the examples below, `LINK_MTU` is used as wolfIP's link-frame budget; wolfIP derives the IPv4 payload MTU from that value after subtracting Ethernet overhead.

```c
static struct wolfIP *ipstack;
static struct my_wolfip_eth eth0;

void my_wolfip_network_init(void)
{
    struct wolfIP_ll_dev *dev;

    wolfIP_init_static(&ipstack);

    eth0.hw = my_hw_open(0);
    my_hw_get_mac(eth0.hw, eth0.mac);

    dev = wolfIP_getdev(ipstack);
    memset(dev, 0, sizeof(*dev));

    memcpy(dev->mac, eth0.mac, sizeof(eth0.mac));
    strncpy(dev->ifname, "e0", sizeof(dev->ifname) - 1);
    dev->mtu = LINK_MTU;
    dev->poll = my_wolfip_eth_poll;
    dev->send = my_wolfip_eth_send;
    dev->priv = &eth0;

    wolfIP_ipconfig_set(
        ipstack,
        atoip4("192.168.1.50"),
        atoip4("255.255.255.0"),
        atoip4("192.168.1.1")
    );
}
```

For multiple physical interfaces, set `WOLFIP_MAX_INTERFACES` in `config.h`, initialize each hardware instance, retrieve each device with `wolfIP_getdev_ex()`, and configure each interface with `wolfIP_ipconfig_set_ex()`.

```c
#define MY_ETH_PORTS 2

static struct wolfIP *ipstack;
static struct my_wolfip_eth eth[MY_ETH_PORTS];

static void my_wolfip_init_one_if(unsigned int if_idx,
                                  const char *ifname,
                                  const char *ip,
                                  const char *mask,
                                  const char *gw)
{
    struct wolfIP_ll_dev *dev = wolfIP_getdev_ex(ipstack, if_idx);

    eth[if_idx].hw = my_hw_open(if_idx);
    my_hw_get_mac(eth[if_idx].hw, eth[if_idx].mac);

    memset(dev, 0, sizeof(*dev));
    memcpy(dev->mac, eth[if_idx].mac, sizeof(eth[if_idx].mac));
    strncpy(dev->ifname, ifname, sizeof(dev->ifname) - 1);
    dev->mtu = LINK_MTU;
    dev->poll = my_wolfip_eth_poll;
    dev->send = my_wolfip_eth_send;
    dev->priv = &eth[if_idx];

    wolfIP_ipconfig_set_ex(ipstack, if_idx, atoip4(ip), atoip4(mask), atoip4(gw));
}

void my_wolfip_network_init_two_ports(void)
{
    wolfIP_init_static(&ipstack);

    my_wolfip_init_one_if(0, "e0", "192.168.1.50", "255.255.255.0", "192.168.1.1");
    my_wolfip_init_one_if(1, "e1", "10.10.10.2",  "255.255.255.0", "10.10.10.1");
}
```

If your build enables wolfIP loopback, do not blindly overwrite interface index 0 unless that is still your physical interface in your configuration. Use `wolfIP_getdev()` for the primary interface, and use explicit `_ex()` indexes only when you have verified the interface layout for that build.

### 5.5 Driving the port

A bare-metal main loop usually becomes:

```c
int main(void)
{
    board_init();
    my_wolfip_network_init();

    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

For an interrupt-driven MAC, keep the ISR small. The ISR should acknowledge the hardware interrupt and wake the network loop or RTOS poll task. Let the `poll` callback drain RX descriptors and let `send` queue TX frames. This keeps all wolfIP stack processing on the same execution path and avoids re-entering the stack from an interrupt.

### 5.6 Driver migration checklist

* Replace pbuf allocation on RX with copying one complete frame into the buffer passed to `ll->poll`.
* Replace pbuf-chain iteration on TX with transmitting the single contiguous frame passed to `ll->send`.
* Move `netif->state` contents to a driver-private structure referenced by `ll->priv`.
* Move MAC address and MTU setup from `netif` fields to `ll->mac` and `ll->mtu`.
* Replace `netif_add()` and `netif_set_default()` with `wolfIP_getdev()` / `wolfIP_getdev_ex()` and `wolfIP_ipconfig_set()` / `wolfIP_ipconfig_set_ex()`.
* Return `0` from `poll` when no frame is available, a positive frame length when one frame was copied, and a negative error for driver errors.
* Return `0` from `send` after the driver has accepted or copied the frame, and `-WOLFIP_EAGAIN` when the TX queue is temporarily full.

---

## 6. Wiring a random-number source

wolfIP requires the application or platform port to provide:

```c
uint32_t wolfIP_getrandom(void);
```

The public header declares this as an external requirement. The stack uses it for values such as the IP packet counter seed, TCP sequence numbers, ephemeral ports, DNS IDs, and DNS retry jitter.

Use a hardware RNG, a properly seeded TRNG/DRBG, or your platform’s cryptographic random source. Do not use a constant, timer-only seed, or unseeded `rand()` in production.

Example using a board hardware RNG:

```c
#include <stdint.h>
#include "wolfip.h"

uint32_t wolfIP_getrandom(void)
{
    uint32_t value;

    if (board_trng_read_u32(&value) == 0) {
        return value;
    }

    /*
     * Fallback should still be platform-specific and non-deterministic.
     * In production, prefer failing closed over returning predictable data.
     */
    return board_entropy_fallback_u32();
}
```

Example using wolfCrypt when your product already initializes wolfSSL/wolfCrypt:

```c
#include <stdint.h>
#include "wolfip.h"
#include <wolfssl/wolfcrypt/random.h>

uint32_t wolfIP_getrandom(void)
{
    static WC_RNG rng;
    static int rng_ready;
    uint32_t value = 0;

    if (!rng_ready) {
        if (wc_InitRng(&rng) != 0) {
            return 0; /* Replace with platform fail handling. */
        }
        rng_ready = 1;
    }

    if (wc_RNG_GenerateBlock(&rng, (byte *)&value, sizeof(value)) != 0) {
        return 0; /* Replace with platform fail handling. */
    }

    return value;
}
```

For production, decide how your product handles RNG failure. Returning zero keeps the code simple but is not acceptable for security-sensitive builds.

---

## 7. Bare-metal socket API migration

### 7.1 wolfIP socket APIs

wolfIP exposes socket-style APIs with an explicit stack pointer:

```c
int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
int wolfIP_sock_bind(struct wolfIP *s, int sockfd,
                     const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog);
int wolfIP_sock_accept(struct wolfIP *s, int sockfd,
                       struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int wolfIP_sock_connect(struct wolfIP *s, int sockfd,
                        const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_send(struct wolfIP *s, int sockfd,
                     const void *buf, size_t len, int flags);
int wolfIP_sock_recv(struct wolfIP *s, int sockfd,
                     void *buf, size_t len, int flags);
int wolfIP_sock_close(struct wolfIP *s, int sockfd);
```

The same header also exposes `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `setsockopt`, `getsockopt`, `getsockname`, `getpeername`, `wolfIP_sock_can_read()`, `wolfIP_sock_can_write()`, and callback registration. `CB_EVENT_READABLE`, `CB_EVENT_WRITABLE`, `CB_EVENT_TIMEOUT`, and `CB_EVENT_CLOSED` are the core event bits.

Important behavioral points:

* On bare metal, drive progress by calling `wolfIP_poll()`.
* Socket calls can return `-WOLFIP_EAGAIN` when an operation would block.
* `wolfIP_sock_connect()` returns `-WOLFIP_EAGAIN` while a TCP connect is in progress and returns `0` once established.
* `wolfIP_sock_accept()` returns `-WOLFIP_EAGAIN` when no connection is ready.
* `wolfIP_sock_send()` queues data into the socket TX buffer and may return `-WOLFIP_EAGAIN` when there is no TX space.
* `wolfIP_sock_recv()` returns available data, `0` on orderly close in close-wait cases, or a negative error when no data or the socket state is invalid.

### 7.2 Address setup

For non-POSIX wolfIP builds, use `struct wolfIP_sockaddr_in`. Ports and IPv4 addresses in socket addresses are stored in network byte order, so use `ee16()` and `ee32()` where appropriate.

```c
static void fill_bind_addr(struct wolfIP_sockaddr_in *addr, uint16_t port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = ee16(port);
    addr->sin_addr.s_addr = ee32(0); /* INADDR_ANY */
}
```

---

## 8. Translating a simple TCP server from lwIP raw/classic API

### 8.1 Original lwIP raw/classic server

This is the common bare-metal lwIP callback style: create a TCP PCB, bind, listen, register an accept callback, register a receive callback on each accepted PCB, call `tcp_recved()` after consuming data, and send with `tcp_write()` plus `tcp_output()`. lwIP’s TCP raw API documentation describes this flow: create with `tcp_new()`, bind with `tcp_bind()`, listen with `tcp_listen()`, accept with `tcp_accept()`, receive through `tcp_recv()`, report consumed bytes with `tcp_recved()`, and send with `tcp_write()` / `tcp_output()`. ([Nongnu][3])

```c
#include "lwip/tcp.h"

#define ECHO_PORT 7

static err_t echo_recv(void *arg,
                       struct tcp_pcb *pcb,
                       struct pbuf *p,
                       err_t err)
{
    struct pbuf *q;

    if (p == NULL) {
        tcp_close(pcb);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    tcp_recved(pcb, p->tot_len);

    for (q = p; q != NULL; q = q->next) {
        err_t wr = tcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
        if (wr != ERR_OK) {
            break;
        }
    }

    tcp_output(pcb);
    pbuf_free(p);

    return ERR_OK;
}

static err_t echo_accept(void *arg,
                         struct tcp_pcb *newpcb,
                         err_t err)
{
    if (err != ERR_OK || newpcb == NULL) {
        return err;
    }

    tcp_recv(newpcb, echo_recv);
    return ERR_OK;
}

void lwip_raw_echo_server_init(void)
{
    struct tcp_pcb *pcb;
    err_t err;

    pcb = tcp_new();
    if (pcb == NULL) {
        return;
    }

    err = tcp_bind(pcb, IP_ADDR_ANY, ECHO_PORT);
    if (err != ERR_OK) {
        tcp_abort(pcb);
        return;
    }

    pcb = tcp_listen(pcb);
    if (pcb == NULL) {
        return;
    }

    tcp_accept(pcb, echo_accept);
}
```

### 8.2 wolfIP bare-metal version

The wolfIP version uses one listening socket plus accepted sockets. It registers a socket callback and uses `wolfIP_poll()` to deliver network progress and events.

```c
#include <string.h>
#include "config.h"
#include "wolfip.h"

#define ECHO_PORT 7

static struct wolfIP *g_ip;
static int g_listen_fd = -1;

static void close_client(int fd)
{
    (void)wolfIP_sock_close(g_ip, fd);
    wolfIP_register_callback(g_ip, fd, NULL, NULL);
}

static void service_client_readable(int fd)
{
    uint8_t buf[512];

    for (;;) {
        int n = wolfIP_sock_recv(g_ip, fd, buf, sizeof(buf), 0);

        if (n > 0) {
            int off = 0;

            while (off < n) {
                int wr = wolfIP_sock_send(g_ip, fd, buf + off, (size_t)(n - off), 0);

                if (wr > 0) {
                    off += wr;
                    continue;
                }

                if (wr == -WOLFIP_EAGAIN) {
                    /*
                     * TX buffer is full. The callback will be called again
                     * when CB_EVENT_WRITABLE is raised.
                     */
                    return;
                }

                close_client(fd);
                return;
            }

            continue;
        }

        if (n == 0) {
            close_client(fd);
            return;
        }

        if (n == -WOLFIP_EAGAIN) {
            return;
        }

        close_client(fd);
        return;
    }
}

static void accept_ready_clients(void)
{
    for (;;) {
        struct wolfIP_sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd;

        memset(&peer, 0, sizeof(peer));

        client_fd = wolfIP_sock_accept(
            g_ip,
            g_listen_fd,
            (struct wolfIP_sockaddr *)&peer,
            &peer_len
        );

        if (client_fd >= 0) {
            wolfIP_register_callback(g_ip, client_fd, echo_socket_cb, NULL);
            continue;
        }

        if (client_fd == -WOLFIP_EAGAIN) {
            return;
        }

        return;
    }
}

void echo_socket_cb(int fd, uint16_t events, void *arg)
{
    (void)arg;

    if (fd == g_listen_fd) {
        if ((events & CB_EVENT_READABLE) != 0) {
            accept_ready_clients();
        }
        return;
    }

    if ((events & CB_EVENT_CLOSED) != 0) {
        close_client(fd);
        return;
    }

    if ((events & CB_EVENT_READABLE) != 0) {
        service_client_readable(fd);
    }

    if ((events & CB_EVENT_WRITABLE) != 0) {
        /*
         * If your application keeps a per-client pending-send queue,
         * resume it here. This minimal echo example sends immediately
         * from the receive path, so there may be nothing to do.
         */
    }
}

int wolfip_echo_server_init(struct wolfIP *ip)
{
    struct wolfIP_sockaddr_in local;
    int ret;

    g_ip = ip;

    g_listen_fd = wolfIP_sock_socket(
        g_ip,
        AF_INET,
        IPSTACK_SOCK_STREAM,
        0
    );

    if (g_listen_fd < 0) {
        return g_listen_fd;
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = ee16(ECHO_PORT);
    local.sin_addr.s_addr = ee32(0); /* INADDR_ANY */

    ret = wolfIP_sock_bind(
        g_ip,
        g_listen_fd,
        (struct wolfIP_sockaddr *)&local,
        sizeof(local)
    );

    if (ret < 0) {
        wolfIP_sock_close(g_ip, g_listen_fd);
        return ret;
    }

    ret = wolfIP_sock_listen(g_ip, g_listen_fd, 1);
    if (ret < 0) {
        wolfIP_sock_close(g_ip, g_listen_fd);
        return ret;
    }

    wolfIP_register_callback(g_ip, g_listen_fd, echo_socket_cb, NULL);
    return 0;
}
```

Main loop:

```c
int main(void)
{
    network_init();

    if (wolfip_echo_server_init(ipstack) < 0) {
        board_fatal_error();
    }

    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

Migration notes:

* lwIP raw API receive callbacks hand you a `pbuf`; wolfIP socket callbacks tell you the socket is readable, then you call `wolfIP_sock_recv()`.
* lwIP requires `tcp_recved()` to advertise consumed receive window; wolfIP handles this inside `wolfIP_sock_recv()`.
* lwIP sends with `tcp_write()` and then `tcp_output()`; wolfIP sends with `wolfIP_sock_send()`, then actual frame output progresses from `wolfIP_poll()`.
* lwIP raw callbacks are PCB-centric; wolfIP callbacks are socket-descriptor-centric.
* lwIP’s listen PCB and active PCBs are separate pool types; wolfIP uses the finite TCP socket array for both.

---

## 9. Translating a simple TCP server from lwIP ALTCP interfaces

### 9.1 Original lwIP ALTCP-style server

lwIP ALTCP is an abstraction layer over the TCP callback API. It is designed so an application can be written against `altcp_*` calls and then use plain TCP, TLS, proxy-connect, or another layer underneath. The official ALTCP documentation says the interface mimics the TCP callback API, replaces `struct tcp_pcb` with `struct altcp_pcb`, and prefixes functions with `altcp_`; it also notes that `altcp_new()` uses an allocator object while TLS or pure-TCP allocation depends on the selected allocator/layer. ([Nongnu][4])

A plain TCP ALTCP echo server may look like this:

```c
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"

#define ECHO_PORT 7

static err_t alt_echo_recv(void *arg,
                           struct altcp_pcb *conn,
                           struct pbuf *p,
                           err_t err)
{
    struct pbuf *q;

    if (p == NULL) {
        altcp_close(conn);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    altcp_recved(conn, p->tot_len);

    for (q = p; q != NULL; q = q->next) {
        err_t wr = altcp_write(conn, q->payload, q->len, TCP_WRITE_FLAG_COPY);
        if (wr != ERR_OK) {
            break;
        }
    }

    altcp_output(conn);
    pbuf_free(p);

    return ERR_OK;
}

static err_t alt_echo_accept(void *arg,
                             struct altcp_pcb *new_conn,
                             err_t err)
{
    if (err != ERR_OK || new_conn == NULL) {
        return err;
    }

    altcp_recv(new_conn, alt_echo_recv);
    return ERR_OK;
}

void lwip_altcp_echo_server_init(void)
{
    struct altcp_pcb *listener;
    err_t err;

    listener = altcp_tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (listener == NULL) {
        return;
    }

    err = altcp_bind(listener, IP_ADDR_ANY, ECHO_PORT);
    if (err != ERR_OK) {
        altcp_abort(listener);
        return;
    }

    listener = altcp_listen(listener);
    if (listener == NULL) {
        return;
    }

    altcp_accept(listener, alt_echo_accept);
}
```

The ALTCP function set includes `altcp_bind()`, `altcp_listen()`, `altcp_accept()`, `altcp_recv()`, `altcp_write()`, `altcp_output()`, and `altcp_close()`, mirroring the raw TCP API. ([Nongnu][5])

### 9.2 wolfIP version

wolfIP does not require an ALTCP abstraction layer for a plain TCP server. Migrate the server to the same `wolfIP_sock_*` pattern shown in the previous section.

Use this mapping:

| lwIP ALTCP                                | wolfIP                                                               |
| ----------------------------------------- | -------------------------------------------------------------------- |
| `struct altcp_pcb *`                      | `int sockfd`                                                         |
| `altcp_tcp_new_ip_type()` / `altcp_new()` | `wolfIP_sock_socket()`                                               |
| `altcp_bind()`                            | `wolfIP_sock_bind()`                                                 |
| `altcp_listen()`                          | `wolfIP_sock_listen()`                                               |
| `altcp_accept()` callback                 | `CB_EVENT_READABLE` on listening socket, then `wolfIP_sock_accept()` |
| `altcp_recv()` callback                   | `CB_EVENT_READABLE`, then `wolfIP_sock_recv()`                       |
| `altcp_recved()`                          | Not needed; receive-window update is handled by `wolfIP_sock_recv()` |
| `altcp_write()`                           | `wolfIP_sock_send()`                                                 |
| `altcp_output()`                          | Usually not needed; transmit progress occurs in `wolfIP_poll()`      |
| `altcp_close()`                           | `wolfIP_sock_close()`                                                |
| `altcp_abort()`                           | `wolfIP_sock_close()` plus application cleanup                       |

For plain TCP, the wolfIP replacement is the echo server from section 8.2.

For ALTCP-over-TLS migrations, separate the migration into two layers:

1. First migrate the TCP transport from ALTCP to wolfIP sockets.
2. Then attach TLS above the wolfIP socket.

wolfIP’s public header includes wolfSSL integration declarations when `WOLFSSL_WOLFIP` is enabled, including `wolfSSL_SetIO_wolfIP()` and `wolfSSL_SetIO_wolfIP_CTX()`. That is the wolfIP-side replacement point for applications that previously used lwIP ALTCP TLS.

Conceptual TLS shape:

```c
/*
 * Pseudocode: exact wolfSSL setup depends on your product's wolfSSL config.
 */
WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
WOLFSSL *ssl = wolfSSL_new(ctx);

wolfSSL_SetIO_wolfIP_CTX(ctx, ipstack);
wolfSSL_SetIO_wolfIP(ssl, client_fd);

ret = wolfSSL_accept(ssl);
```

Keep in mind that TLS handshakes also need nonblocking progress. Under bare metal, call the TLS accept/read/write functions when the socket is readable or writable, and keep calling `wolfIP_poll()`.

---

## 10. RTOS integration

### 10.1 What the FreeRTOS BSD wrapper does

wolfIP includes a FreeRTOS POSIX-style socket wrapper in `src/port/freeRTOS/bsd_socket.c` and a matching header in `src/port/freeRTOS/bsd_socket.h`.

The wrapper provides BSD-like functions:

```c
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int send(int sockfd, const void *buf, size_t len, int flags);
int sendto(int sockfd, const void *buf, size_t len, int flags,
           const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen);
int recv(int sockfd, void *buf, size_t len, int flags);
int recvfrom(int sockfd, void *buf, size_t len, int flags,
             struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);
int close(int sockfd);
```

The header also maps `SOCK_STREAM` to `IPSTACK_SOCK_STREAM` and `SOCK_DGRAM` to `IPSTACK_SOCK_DGRAM`, and exposes `wolfip_freertos_socket_init()`.

Internally, the FreeRTOS port uses:

* a global `struct wolfIP *g_ipstack`;
* a global mutex `g_lock`;
* a public file-descriptor table with entries containing `internal_fd`, `ready_sem`, and `wait_events`;
* one binary semaphore per public socket;
* a poll task that calls `wolfIP_poll()`;
* callbacks from wolfIP that wake blocked tasks by giving the socket’s semaphore.

The FreeRTOS poll task locks the stack, calls `wolfIP_poll(ipstack, now_ms)`, unlocks the stack, bounds the next sleep between a minimum and maximum, converts milliseconds to ticks, and then calls `vTaskDelay()`. The default wrapper constants include `WOLFIP_FREERTOS_BSD_MAX_FDS 16`, `WOLFIP_FREERTOS_POLL_MAX_MS 20`, and `WOLFIP_FREERTOS_POLL_MIN_MS 5`.

### 10.2 Blocking semantics in the wrapper

The underlying wolfIP socket calls are nonblocking-style: they may return `-WOLFIP_EAGAIN`. The FreeRTOS wrapper turns that into blocking BSD-like behavior:

1. Lock the wolfIP core mutex.
2. Call the corresponding `wolfIP_sock_*` function.
3. If it succeeds, unlock and return.
4. If it returns a hard error, unlock and return `-1`.
5. If it returns `-WOLFIP_EAGAIN`, register a callback for the needed event bits.
6. Clear the socket semaphore.
7. Unlock the core mutex.
8. Block on the semaphore.
9. Retry the operation when the callback wakes the task.

For example:

* `accept()` waits for `CB_EVENT_READABLE` or `CB_EVENT_CLOSED`;
* `connect()` waits for `CB_EVENT_WRITABLE` or `CB_EVENT_CLOSED`;
* `send()` waits for `CB_EVENT_WRITABLE` or `CB_EVENT_CLOSED`;
* `recv()` waits for `CB_EVENT_READABLE` or `CB_EVENT_CLOSED`;
* `close()` may wait for `CB_EVENT_CLOSED`.

The wrapper’s callback does not perform socket I/O. It checks whether the delivered event intersects the waiting event mask and then gives the socket’s semaphore.

This is the most important RTOS design rule: do not block while holding the wolfIP core lock, and do not call BSD wrapper functions from the wolfIP callback path if the poll task holds the core lock while dispatching callbacks.

---

## 11. Porting wolfIP to a new RTOS

Use the FreeRTOS wrapper as a template. The required OS primitives are small.

### 11.1 Required OS primitives

Your RTOS port needs:

| Primitive                                 | Used for                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------- |
| Mutex                                     | Protect all calls into the wolfIP core and `wolfIP_poll()`.                   |
| Binary semaphore or event object          | Put application tasks to sleep while waiting for socket readiness.            |
| Task/thread creation                      | Run the wolfIP poll task.                                                     |
| Tick/time API                             | Provide `now_ms` to `wolfIP_poll()`.                                          |
| Delay/sleep API                           | Sleep the poll task between poll cycles.                                      |
| Critical section or mutex around FD table | Protect public FD allocation/freeing if not already covered by the core lock. |

### 11.2 Suggested port architecture

Use this architecture for a new OS:

```text
+-------------------------+
| Application task        |
| socket/send/recv/etc.   |
+------------+------------+
             |
             v
+-------------------------+
| OS BSD wrapper          |
| - public fd table       |
| - per-fd semaphore      |
| - core mutex            |
+------------+------------+
             |
             v
+-------------------------+
| wolfIP core             |
| wolfIP_sock_* APIs      |
| wolfIP_poll()           |
+------------+------------+
             |
             v
+-------------------------+
| Link-layer driver       |
| ll->poll(), ll->send()  |
+-------------------------+
```

### 11.3 Porting steps

1. **Create the global port state**

```c
struct os_wolfip_fd {
    int in_use;
    int internal_fd;
    os_sem_t ready_sem;
    volatile uint16_t wait_events;
};

static struct wolfIP *g_ipstack;
static os_mutex_t g_core_lock;
static struct os_wolfip_fd g_fds[OS_WOLFIP_MAX_FDS];
```

2. **Create a poll task**

```c
static void wolfip_os_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;

    for (;;) {
        uint64_t now_ms = os_time_millis();
        uint32_t next_ms;

        os_mutex_lock(&g_core_lock);
        next_ms = (uint32_t)wolfIP_poll(ipstack, now_ms);
        os_mutex_unlock(&g_core_lock);

        if (next_ms < OS_WOLFIP_POLL_MIN_MS) {
            next_ms = OS_WOLFIP_POLL_MIN_MS;
        }

        if (next_ms > OS_WOLFIP_POLL_MAX_MS) {
            next_ms = OS_WOLFIP_POLL_MAX_MS;
        }

        os_sleep_ms(next_ms);
    }
}
```

3. **Initialize the wrapper**

```c
int wolfip_os_socket_init(struct wolfIP *ipstack,
                          int poll_task_priority,
                          size_t poll_task_stack_size)
{
    int i;

    if (ipstack == NULL) {
        return -WOLFIP_EINVAL;
    }

    os_mutex_create(&g_core_lock);

    for (i = 0; i < OS_WOLFIP_MAX_FDS; i++) {
        g_fds[i].in_use = 0;
        g_fds[i].internal_fd = -1;
        g_fds[i].wait_events = 0;
        os_sem_create_binary(&g_fds[i].ready_sem);
    }

    g_ipstack = ipstack;

    if (os_task_create(wolfip_os_poll_task,
                       "wolfip_poll",
                       poll_task_stack_size,
                       ipstack,
                       poll_task_priority) != 0) {
        return -WOLFIP_ENOMEM;
    }

    return 0;
}
```

4. **Bridge wolfIP callbacks to OS wakeups**

```c
static void wolfip_os_socket_cb(int internal_fd,
                                uint16_t events,
                                void *arg)
{
    struct os_wolfip_fd *entry = (struct os_wolfip_fd *)arg;

    (void)internal_fd;

    if (entry == NULL) {
        return;
    }

    if ((events & entry->wait_events) != 0) {
        os_sem_give(&entry->ready_sem);
    }
}
```

5. **Prepare a wait while the core is locked**

```c
static void prepare_wait_locked(struct os_wolfip_fd *entry,
                                uint16_t wait_events)
{
    entry->wait_events = wait_events;
    os_sem_drain(&entry->ready_sem);

    wolfIP_register_callback(
        g_ipstack,
        entry->internal_fd,
        wolfip_os_socket_cb,
        entry
    );
}
```

6. **Wrap each socket function**

Example `recv()` wrapper:

```c
int recv(int public_fd, void *buf, size_t len, int flags)
{
    struct os_wolfip_fd *entry;
    int ret;

    if (!fd_valid(public_fd)) {
        return -1;
    }

    entry = &g_fds[public_fd];

    for (;;) {
        os_mutex_lock(&g_core_lock);

        ret = wolfIP_sock_recv(
            g_ipstack,
            entry->internal_fd,
            buf,
            len,
            flags
        );

        if (ret >= 0) {
            os_mutex_unlock(&g_core_lock);
            return ret;
        }

        if (ret != -WOLFIP_EAGAIN) {
            os_mutex_unlock(&g_core_lock);
            os_set_errno_from_wolfip(ret);
            return -1;
        }

        prepare_wait_locked(
            entry,
            (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED)
        );

        os_mutex_unlock(&g_core_lock);

        if (os_sem_take(&entry->ready_sem, OS_WAIT_FOREVER) != 0) {
            os_set_errno_from_wolfip(-WOLFIP_EAGAIN);
            return -1;
        }
    }
}
```

Repeat the same pattern for:

* `accept()` waiting on `CB_EVENT_READABLE | CB_EVENT_CLOSED`;
* `connect()` waiting on `CB_EVENT_WRITABLE | CB_EVENT_CLOSED`;
* `send()` waiting on `CB_EVENT_WRITABLE | CB_EVENT_CLOSED`;
* `close()` waiting on `CB_EVENT_CLOSED` when close returns `-WOLFIP_EAGAIN`.

### 11.4 RTOS locking rules

Follow these rules in the new OS port:

* Hold the core mutex while calling `wolfIP_sock_*`.
* Hold the core mutex while calling `wolfIP_poll()`.
* Do not hold the core mutex while blocking on a semaphore.
* Keep wolfIP callbacks short; wake tasks, set flags, or post events only.
* Do not call blocking wrapper APIs from inside the callback.
* Protect the public FD table consistently.
* Delete per-FD semaphores when closing sockets.
* Clear callbacks before freeing FD entries.
* Decide whether your wrapper returns BSD-style `-1` plus `errno`, or wolfIP negative errors directly. Be consistent.

### 11.5 Poll-task timing

The FreeRTOS wrapper bounds the poll delay between 5 ms and 20 ms by default. That is a reasonable starting point for an RTOS port because it prevents the poll task from spinning while still giving TCP timers, ACKs, retransmissions, and queued TX work regular progress.

For latency-sensitive products, reduce the maximum delay. For power-sensitive products, allow a larger maximum delay only after confirming that retransmission behavior, DNS, DHCP, and application latency still meet product requirements.

---

## 12. Migration checklist

### 12.1 Before changing code

* Count maximum simultaneous TCP sockets, including listeners.
* Count UDP sockets, including DNS/DHCP/application use.
* Decide whether ICMP, raw sockets, packet sockets, forwarding, loopback, multicast, or HTTP are required.
* Decide the MTU and RX/TX buffer sizes.
* Identify all lwIP raw callbacks, Netconn tasks, socket users, and ALTCP/TLS users.
* Identify your hardware RNG or cryptographic RNG source.

### 12.2 Configuration

* Replace `lwipopts.h` pool tuning with a short wolfIP `config.h`.
* Set `MAX_TCPSOCKETS`, `MAX_UDPSOCKETS`, `MAX_ICMPSOCKETS`.
* Set `RXBUF_SIZE`, `TXBUF_SIZE`, `LINK_MTU`, and `MAX_NEIGHBORS`.
* Enable only the optional socket families and protocol features you need.
* For static IP, call `wolfIP_ipconfig_set()` or `wolfIP_ipconfig_set_ex()` during network init.

### 12.3 Network drivers

* Move driver state from `netif->state` to `wolfIP_ll_dev.priv`.
* Move MAC address and MTU setup from `netif` fields to `wolfIP_ll_dev`.
* Replace RX pbuf allocation with a `poll` function that copies one complete frame into wolfIP's buffer.
* Replace TX pbuf-chain traversal with a `send` function that accepts one contiguous frame.
* Initialize each interface with `wolfIP_getdev()` or `wolfIP_getdev_ex()` plus `wolfIP_ipconfig_set()` or `wolfIP_ipconfig_set_ex()`.

### 12.4 Bare metal

* Initialize wolfIP with `wolfIP_init_static()` or `wolfIP_init()`.
* Fill `wolfIP_ll_dev` with `poll`, `send`, MAC, MTU, and driver context.
* Provide `wolfIP_getrandom()`.
* Call `wolfIP_poll()` regularly.
* Replace lwIP PCBs with wolfIP socket descriptors.
* Replace raw/ALTCP callbacks with socket callbacks plus `wolfIP_sock_recv()` / `wolfIP_sock_send()`.

### 12.5 RTOS

* Add one poll task.
* Add one core mutex.
* Add a public FD table if you want BSD-like descriptors.
* Add one semaphore/event object per FD.
* Convert `-WOLFIP_EAGAIN` into wait-and-retry behavior.
* Wake blocked tasks from `wolfIP_register_callback()` callbacks.
* Never block while holding the wolfIP core mutex.

---

## 13. Common migration pitfalls

### 13.1 Forgetting that the listener consumes a TCP socket

If `MAX_TCPSOCKETS` is 4, a server can have one listener and at most three accepted TCP clients at the same time.

### 13.2 Expecting lwIP-style separate listen and active pools

lwIP has `MEMP_NUM_TCP_PCB` and `MEMP_NUM_TCP_PCB_LISTEN`. wolfIP has one TCP socket array, so size it for both roles.

### 13.3 Calling `wolfIP_sock_accept()` only once

A callback may indicate that the listener is readable. Accept in a loop until `-WOLFIP_EAGAIN` so you drain all ready connection events.

### 13.4 Treating `wolfIP_sock_send()` as immediate wire transmission

`wolfIP_sock_send()` queues data. Actual frame transmission progresses from `wolfIP_poll()`.

### 13.5 Implementing a weak RNG

TCP sequence numbers, DNS IDs, source ports, and other protocol values need unpredictable randomness. Wire a real RNG.

### 13.6 Blocking inside an RTOS callback

In the FreeRTOS-style design, callbacks wake tasks. They should not call blocking socket wrappers.

### 13.7 Holding the core lock while sleeping

Lock while calling wolfIP. Unlock before waiting on a semaphore. This prevents deadlocks and allows the poll task to make progress.

---

## 14. Quick API mapping

| Task                | lwIP raw/classic                  | lwIP ALTCP                                | wolfIP bare metal                                        |
| ------------------- | --------------------------------- | ----------------------------------------- | -------------------------------------------------------- |
| Create TCP endpoint | `tcp_new()`                       | `altcp_tcp_new_ip_type()` / `altcp_new()` | `wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0)` |
| Bind                | `tcp_bind()`                      | `altcp_bind()`                            | `wolfIP_sock_bind()`                                     |
| Listen              | `tcp_listen()`                    | `altcp_listen()`                          | `wolfIP_sock_listen()`                                   |
| Accept              | `tcp_accept()` callback           | `altcp_accept()` callback                 | callback event + `wolfIP_sock_accept()`                  |
| Receive             | `tcp_recv()` callback with `pbuf` | `altcp_recv()` callback with `pbuf`       | callback event + `wolfIP_sock_recv()`                    |
| Mark received       | `tcp_recved()`                    | `altcp_recved()`                          | Not needed in application                                |
| Send                | `tcp_write()`                     | `altcp_write()`                           | `wolfIP_sock_send()`                                     |
| Flush output        | `tcp_output()`                    | `altcp_output()`                          | `wolfIP_poll()` progresses output                        |
| Close               | `tcp_close()`                     | `altcp_close()`                           | `wolfIP_sock_close()`                                    |
| Abort               | `tcp_abort()`                     | `altcp_abort()`                           | `wolfIP_sock_close()` plus cleanup                       |
| Main progress       | Ethernet input + lwIP timers      | Ethernet input + lwIP timers              | `wolfIP_poll()`                                          |
| TLS layering        | Usually ALTCP TLS                 | ALTCP TLS                                 | wolfSSL over wolfIP socket                               |



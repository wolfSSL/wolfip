# wolfIP Porting Guide

## Table of Contents

- [1. Scope](#1-scope)
- [2. Where a port plugs in](#2-where-a-port-plugs-in)
- [3. The link-layer device interface](#3-the-link-layer-device-interface)
- [4. Designing a device driver](#4-designing-a-device-driver)
  - [4.1 The driver contract](#41-the-driver-contract)
  - [4.2 A driver without DMA (PIO / host-backed)](#42-a-driver-without-dma-pio--host-backed)
  - [4.3 A driver with DMA: descriptor rings](#43-a-driver-with-dma-descriptor-rings)
  - [4.4 DMA ownership and the poll path](#44-dma-ownership-and-the-poll-path)
  - [4.5 DMA ownership and the send path](#45-dma-ownership-and-the-send-path)
  - [4.6 Cache coherency on DMA-capable cores](#46-cache-coherency-on-dma-capable-cores)
  - [4.7 Descriptor format gotchas](#47-descriptor-format-gotchas)
  - [4.8 PHY and MDIO bring-up](#48-phy-and-mdio-bring-up)
  - [4.9 Wiring the driver into the stack](#49-wiring-the-driver-into-the-stack)
  - [4.10 Driver design checklist](#410-driver-design-checklist)
- [5. Wiring a random-number source](#5-wiring-a-random-number-source)
- [6. Porting to a new operating system](#6-porting-to-a-new-operating-system)
  - [6.1 What an OS port has to provide](#61-what-an-os-port-has-to-provide)
  - [6.2 The poll task: the heartbeat of the stack](#62-the-poll-task-the-heartbeat-of-the-stack)
  - [6.3 The core mutex](#63-the-core-mutex)
  - [6.4 Building bsd_socket.c: the public FD table](#64-building-bsd_socketc-the-public-fd-table)
  - [6.5 Turning -WOLFIP_EAGAIN into blocking](#65-turning--wolfip_eagain-into-blocking)
  - [6.6 Bridging wolfIP callbacks to OS wakeups](#66-bridging-wolfip-callbacks-to-os-wakeups)
  - [6.7 A complete wrapper: recv()](#67-a-complete-wrapper-recv)
  - [6.8 Initialization and teardown](#68-initialization-and-teardown)
- [7. Case study: the Zephyr port](#7-case-study-the-zephyr-port)
- [8. RTOS locking rules](#8-rtos-locking-rules)
- [9. Porting checklist](#9-porting-checklist)
- [10. Common porting pitfalls](#10-common-porting-pitfalls)

---

## 1. Scope

This guide is for developers bringing wolfIP up on new hardware or under a new
operating system. It covers the two ports almost every integration needs:

- a **link-layer device driver** that moves Ethernet frames between wolfIP and
  the MAC — both the simple programmed-I/O case and the DMA descriptor-ring
  case;
- an **operating-system integration layer** that runs `wolfIP_poll()`,
  serializes access to the stack, and (optionally) exposes BSD-style blocking
  sockets to application tasks.

The snippets are drawn from the in-tree ports: the POSIX TAP driver
(`src/port/posix/tap_linux.c`), the NXP LPC and Vorago VA416xx Ethernet
drivers (`src/port/lpc_enet/`, `src/port/va416xx/`), the AMD/Xilinx GEM driver
(`src/port/amd/`), the FreeRTOS BSD wrapper (`src/port/freeRTOS/bsd_socket.c`),
and the Zephyr port (`port/zephyr/`). They are trimmed to show the porting
pattern, not every register or error path of a production driver.

If you are coming from lwIP, read this guide alongside
[`migrating_from_lwIP.md`](migrating_from_lwIP.md), which maps lwIP concepts
(`netif`, `pbuf`, raw/ALTCP callbacks, `lwipopts.h`) onto the wolfIP
equivalents covered here.

---

## 2. Where a port plugs in

wolfIP is a single-threaded, statically-allocated stack. It does not own a
thread, it does not allocate memory at runtime, and it never blocks. All
progress happens inside one function:

```c
uint32_t wolfIP_poll(struct wolfIP *s, uint64_t now_ms);
```

Every call to `wolfIP_poll()` does four things in order:

1. asks each link-layer device for one received frame (`ll->poll`);
2. processes that frame through ARP / IP / TCP / UDP / ICMP;
3. fires registered socket callbacks for any state changes (readable,
   writable, closed, timeout);
4. drains pending TX by handing frames to the driver (`ll->send`).

A port therefore has exactly two contact surfaces:

```text
        application / sockets
                 |
        +--------v---------+     OS integration:
        |  wolfIP core     |  <- call wolfIP_poll() on a timer/thread,
        |  wolfIP_poll()   |     serialize with a mutex, wake blocked tasks
        +--------+---------+
                 |
        +--------v---------+     device driver:
        | ll->poll()       |  <- copy one RX frame up
        | ll->send()       |  <- copy one TX frame to hardware
        +------------------+
```

The driver surface is section 4. The OS surface is section 6. On bare metal
you only need the driver — `main()` calls `wolfIP_poll()` in a loop and that is
the whole "OS port."

---

## 3. The link-layer device interface

A driver is one `struct wolfIP_ll_dev` per interface (from `wolfip.h`):

```c
struct wolfIP_ll_dev {
    uint8_t mac[6];
    char ifname[16];
    uint8_t non_ethernet;
    uint32_t mtu;
    /* poll function */
    int (*poll)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    /* send function */
    int (*send)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    /* optional context private pointer */
    void *priv;
    /* ... optional VLAN fields ... */
};
```

You fill in `mac`, `ifname`, `mtu`, `poll`, `send`, and optionally `priv` (a
back-pointer to your driver state, the wolfIP equivalent of lwIP's
`netif->state`). The stack retrieves the primary device with
`wolfIP_getdev(s)` and additional interfaces with `wolfIP_getdev_ex(s, idx)`.

`buf` is always a **single, contiguous, linear** frame buffer owned by the
stack — there is no `pbuf` chain to walk. The frame includes the full Ethernet
header. Your driver must not retain the `buf` pointer after the callback
returns.

---

## 4. Designing a device driver

### 4.1 The driver contract

Both callbacks have a small, strict contract. Getting the return values right
is what makes the stack progress correctly.

**`poll(ll, buf, len)`** — "give me at most one received frame":

| Return | Meaning |
|---|---|
| `> 0` | A complete frame of this many bytes was copied into `buf`. |
| `0` | No frame is available right now. |
| `< 0` | Driver error; the stack skips RX processing this cycle. |

**`send(ll, buf, len)`** — "transmit this one complete frame":

| Return | Meaning |
|---|---|
| `> 0` or `0` | The driver accepted/queued the frame. |
| `-WOLFIP_EAGAIN` | TX ring/queue is full; the stack retries on a later poll. |
| other `< 0` | Hard error (e.g. frame too large). |

Two rules follow directly from this contract and are worth internalizing
before writing a line of driver code:

- **One frame per call.** `poll` returns *one* frame even if several are
  queued; `wolfIP_poll()` calls it again next cycle. `send` transmits exactly
  the bytes handed to it.
- **Never block.** Both callbacks run inline inside `wolfIP_poll()`. If the
  hardware is busy, return `0` (poll) or `-WOLFIP_EAGAIN` (send) and let the
  next poll cycle make progress.

### 4.2 A driver without DMA (PIO / host-backed)

The simplest possible driver does a register/FIFO read on poll and a
register/FIFO write on send. The POSIX TAP driver is the canonical minimal
example — the "hardware" is a host file descriptor, but the shape is identical
to a small MCU MAC that exposes an RX/TX FIFO (`src/port/posix/tap_linux.c`):

```c
static int tap_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct pollfd pfd;
    int ret;
    (void)ll;
    pfd.fd = tap_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2);
    if (ret < 0) {
        perror("poll");
        return -1;          /* driver error */
    }
    if (ret == 0) {
        return 0;           /* nothing to receive */
    }
    return read(tap_fd, buf, len);   /* one frame copied into buf */
}

static int tap_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    return write(tap_fd, buf, len);  /* transmit the contiguous frame */
}
```

For a real MCU without DMA the body changes but the skeleton does not:

```c
static int my_pio_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    uint32_t flen;
    (void)ll;

    if (!(MAC_RX_STATUS & RX_FRAME_READY))
        return 0;                         /* no frame: return 0, never block */

    flen = MAC_RX_LEN & RX_LEN_MASK;
    if (flen > len)                        /* never overflow the stack buffer */
        flen = len;

    /* Drain the MAC RX FIFO word by word into the linear stack buffer. */
    for (uint32_t i = 0; i < flen; i += 4)
        *(uint32_t *)((uint8_t *)buf + i) = MAC_RX_FIFO;

    MAC_RX_CMD = RX_RELEASE;               /* hand the slot back to the MAC */
    return (int)flen;
}

static int my_pio_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    if (!(MAC_TX_STATUS & TX_FIFO_FREE))
        return -WOLFIP_EAGAIN;             /* full: ask the stack to retry */

    MAC_TX_LEN = len;
    for (uint32_t i = 0; i < len; i += 4)
        MAC_TX_FIFO = *(uint32_t *)((uint8_t *)buf + i);

    MAC_TX_CMD = TX_START;
    return (int)len;
}
```

No descriptor rings, no cache maintenance, no ownership flags. If your MAC can
copy a whole frame in and out through registers or a FIFO, this is all you
need. Most of the remaining complexity in this section exists only because DMA
introduces shared memory between the CPU and the MAC.

### 4.3 A driver with DMA: descriptor rings

A DMA-capable MAC does not use FIFOs. Instead the CPU and the MAC share a ring
of **descriptors** in RAM. Each descriptor points at a buffer and carries an
**OWN** bit that says whether the CPU or the MAC currently owns that slot. The
driver's job becomes:

- on RX, find a descriptor the MAC has filled (OWN handed back to CPU), copy
  the frame out, and re-arm the descriptor (OWN back to MAC);
- on TX, find a free descriptor (CPU owns it), copy the frame in, and set OWN
  to hand it to the MAC.

Declare the rings and buffers as static, aligned storage. The LPC driver uses
the Synopsys DesignWare "enhanced" 4-word descriptor
(`src/port/lpc_enet/lpc_enet.c`):

```c
struct eth_desc {
    volatile uint32_t des0;
    volatile uint32_t des1;
    volatile uint32_t des2;
    volatile uint32_t des3;
};

#define RX_DESC_COUNT  4U
#define TX_DESC_COUNT  3U

static struct eth_desc rx_ring[RX_DESC_COUNT] __attribute__((aligned(32)));
static struct eth_desc tx_ring[TX_DESC_COUNT] __attribute__((aligned(32)));
static uint8_t rx_buffers[RX_DESC_COUNT][RX_BUF_SIZE] __attribute__((aligned(32)));
static uint8_t tx_buffers[TX_DESC_COUNT][TX_BUF_SIZE] __attribute__((aligned(32)));

static uint32_t rx_idx;   /* next RX descriptor the CPU will inspect */
static uint32_t tx_idx;   /* next TX descriptor the CPU will fill */
```

Alignment matters: many DMA engines require descriptors and buffers aligned to
the burst size (16 or 32 bytes), and on systems with a data cache the buffers
must be aligned to a cache line so that a clean/invalidate does not disturb
neighbouring data (see 4.6). On some parts the DMA can only reach a specific
RAM bank — the VA416xx driver pins all rings and buffers into a dedicated
section because the Ethernet DMA cannot access the code-bus RAM
(`src/port/va416xx/va416xx_eth.c`):

```c
static struct eth_desc rx_ring[RX_DESC_COUNT]
    __attribute__((aligned(16), section(".dma_bss")));
```

### 4.4 DMA ownership and the poll path

The RX poll walks to the current descriptor, checks the OWN bit, and bails out
with `0` if the MAC still owns it (no frame yet). Otherwise it copies the frame
out and re-arms the slot. The LPC enhanced-descriptor version
(`src/port/lpc_enet/lpc_enet.c`):

```c
static int eth_poll(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t status, frame_len = 0;
    (void)dev;

    desc = &rx_ring[rx_idx];
    if (desc->des3 & RDES3_OWN)
        return 0;                      /* MAC still owns it: no frame */

    status = desc->des3;
    if ((status & (RDES3_FS | RDES3_LS)) == (RDES3_FS | RDES3_LS)) {
        frame_len = status & RDES3_PL_MASK;
        if (frame_len > len) frame_len = len;     /* clamp to stack buffer */
        if (frame_len > 0)
            memcpy(frame, rx_buffers[rx_idx], frame_len);
    }

    /* Re-arm: point the descriptor back at its buffer and give OWN to the
     * MAC so it can receive into this slot again. */
    desc->des0 = DMA_ADDR(rx_buffers[rx_idx]);
    desc->des1 = 0; desc->des2 = 0;
    __asm volatile ("dsb sy" ::: "memory");
    desc->des3 = RDES3_OWN | RDES3_IOC | RDES3_BUF1V;
    __asm volatile ("dsb sy" ::: "memory");
    ETH_DMACRXDTPR = DMA_ADDR(desc);   /* poke the DMA tail pointer */
    rx_idx = (rx_idx + 1) % RX_DESC_COUNT;

    return (int)frame_len;
}
```

Note the checks: only accept a descriptor that is both the **first and last
segment** of a frame (`FS | LS`) — a single un-fragmented Ethernet frame — and
always clamp `frame_len` to the buffer length the stack passed in.

### 4.5 DMA ownership and the send path

The send path is the mirror image: check that the CPU owns the next TX
descriptor, copy the frame in, pad to the 60-byte Ethernet minimum, then set
OWN to hand it to the MAC. Crucially, if the CPU does **not** own the
descriptor (the ring is full), return `-WOLFIP_EAGAIN` so the stack retries
later instead of corrupting an in-flight frame:

```c
static int eth_send(struct wolfIP_ll_dev *dev, void *frame, uint32_t len)
{
    struct eth_desc *desc;
    uint32_t dma_len, next;
    (void)dev;

    if (len == 0 || len > TX_BUF_SIZE) return -1;          /* hard error */
    desc = &tx_ring[tx_idx];
    if (desc->des3 & TDES3_OWN) return -2;                 /* ring full */

    memcpy(tx_buffers[tx_idx], frame, len);
    dma_len = (len < FRAME_MIN_LEN) ? FRAME_MIN_LEN : len; /* pad to 60 */
    if (dma_len > len) memset(tx_buffers[tx_idx] + len, 0, dma_len - len);

    desc->des0 = DMA_ADDR(tx_buffers[tx_idx]);
    desc->des1 = 0;
    desc->des2 = (dma_len & TDES2_B1L_MASK);
    __asm volatile ("dsb sy" ::: "memory");
    /* OWN is the doorbell: write the descriptor body first, OWN last. */
    desc->des3 = (dma_len & TDES3_FL_MASK) | TDES3_FD | TDES3_LD | TDES3_OWN;
    __asm volatile ("dsb sy" ::: "memory");

    ETH_DMACSR = DMACSR_TBU;
    next = (tx_idx + 1) % TX_DESC_COUNT;
    ETH_DMACTXDTPR = DMA_ADDR(&tx_ring[next]);             /* kick TX DMA */
    tx_idx = next;
    return (int)len;
}
```

> The wolfIP core treats any negative `send` return that is not a hard error as
> "try again later." The AMD GEM driver makes this explicit by returning
> `-WOLFIP_EAGAIN` when the BD ring is backed up (`src/port/amd/common/gem_core.c`):
> `if ((gem_tx_ring[idx].status & TXBUF_USED) == 0) return -WOLFIP_EAGAIN;`

The ordering — **write the descriptor fields, memory barrier, then write the
OWN bit, barrier, then kick the DMA** — is not optional. The OWN bit is a
doorbell; if it becomes visible to the MAC before the buffer address and length
do, the MAC will DMA garbage.

### 4.6 Cache coherency on DMA-capable cores

On a core with a data cache and no hardware cache-coherent DMA (Cortex-A,
Cortex-M7, etc.) the descriptors and buffers live in cacheable memory that both
the CPU and the MAC touch. You must bracket every DMA hand-off with cache
maintenance, or the CPU and MAC will see different memory:

- **Before the MAC reads** CPU-written data (a TX buffer, a re-armed
  descriptor): **clean** (write back) the cache so the MAC sees your writes.
- **Before the CPU reads** MAC-written data (an RX buffer, a completed
  descriptor's status/OWN): **invalidate** the cache so you do not read a stale
  copy.

The AMD GEM port wraps the BD ring with exactly these operations. RX poll
(`src/port/amd/ip/gem_rx_poll.c`):

```c
cache_inval(gem_rx_ring, sizeof(gem_rx_ring));      /* see fresh OWN/status */
if (!(gem_rx_ring[gem_rx_next].addr & RXBUF_OWN_SW))
    return 0;

frame_len = gem_rx_ring[gem_rx_next].status & RXBUF_LEN_MASK;
cache_inval(gem_rx_buf_pool[gem_rx_next], frame_len);   /* see fresh payload */
memcpy(buf, gem_rx_buf_pool[gem_rx_next], copy);

/* re-arm, then push the descriptor back to memory for the MAC */
gem_rx_ring[gem_rx_next].addr = addr;               /* OWN=0 -> MAC owns */
cache_clean(&gem_rx_ring[gem_rx_next], sizeof(gem_rx_ring[gem_rx_next]));
__asm__ volatile ("dsb" ::: "memory");
```

TX send (`src/port/amd/common/gem_core.c`):

```c
/* The USED bit is written back by MAC DMA - invalidate so the CPU does not
 * see the stale USED=0 we wrote when we last armed this BD. */
cache_inval(&gem_tx_ring[idx], sizeof(gem_tx_ring[idx]));
...
memcpy(gem_tx_buf_pool[idx], buf, len);
cache_clean(gem_tx_buf_pool[idx], len);             /* MAC must see the frame */
...
gem_tx_ring[idx].status = status;                   /* USED=0 -> ready for MAC */
cache_clean(&gem_tx_ring[idx], sizeof(gem_tx_ring[idx]));
GEM_NWCTRL |= NWCTRL_STARTTX;
```

The helper semantics, from `src/port/amd/arch/aarch64/cache.h`: *"`cache_clean()`
writes back dirty lines before DMA reads; `cache_inval()` invalidates lines so
CPU reads pull fresh"* data the MAC just wrote.

Two traps to avoid:

- **Cache-line aliasing.** If a buffer is not cache-line aligned and padded to
  a full line, an invalidate can throw away an adjacent variable, or a clean can
  overwrite MAC-written bytes. Align DMA buffers to the cache line.
- **Barriers are not cache ops.** `dsb`/`__DSB()` orders memory accesses but
  does not move data between cache and RAM. You need *both*: the cache op for
  coherency and the barrier for ordering. The MCU drivers that run cache-off
  (LPC, VA416xx) use only `dsb`; the cache-on AMD driver uses both.

If your platform has an MPU/MMU, an even simpler option during bring-up is to
mark the DMA region **non-cacheable** and drop the per-frame cache ops
entirely, at a small throughput cost.

### 4.7 Descriptor format gotchas

DMA descriptor layouts vary even within one IP family, and the differences are
easy to get subtly wrong. The in-tree drivers document two real examples worth
knowing about before you write your own:

- **Enhanced vs. normal descriptors.** The LPC driver uses the Synopsys
  "enhanced" format where control bits (FD/LD/OWN) live in `des3`. The VA416xx
  uses the same Synopsys GMAC in **normal/legacy** format, where on TX *only*
  the OWN bit lives in `des0` and all frame control (FS/LS/IC) lives in `des1`
  — `des0`'s other bits are status the DMA writes back. Loading control bits
  into the wrong word makes the DMA advance linearly and never transmit.

- **Ring wrap: tail pointer vs. chain vs. ring bit.** The LPC enhanced format
  wraps via a tail-pointer register. The VA416xx normal format must use
  **chain mode** (each `des3` points at the next descriptor) on TX, because the
  DMA overwrites `des0` on completion and a ring-mode "end of ring" bit stored
  there would be destroyed, sending the DMA walking off the end of the ring
  into adjacent memory (`src/port/va416xx/va416xx_eth.c`):

  ```c
  /* Chain: each descriptor points to the next; last wraps to first.
   * The DMA only writes back to des0; des1/des2/des3 survive, so the
   * chain pointer in des3 wraps the ring reliably. */
  tx_ring[i].des3 = (uint32_t)&tx_ring[(i + 1U) % TX_DESC_COUNT];
  ```

The lesson: read your MAC's reference driver (vendor SDK, U-Boot, Linux) to
confirm which descriptor variant the silicon actually implements, then copy
that variant's bit layout exactly.

### 4.8 PHY and MDIO bring-up

The MAC moves frames; the **PHY** brings the copper link up. You talk to it
over the MDIO (MII management) bus to reset it, start auto-negotiation, and
read back the negotiated speed/duplex so you can program the MAC to match. The
LPC driver's MDIO accessors are a compact reference
(`src/port/lpc_enet/lpc_enet.c`):

```c
static uint16_t mdio_read(uint32_t phy, uint32_t reg)
{
    uint32_t cr;
    mdio_wait();                                   /* wait for MII not-busy */
    cr = ETH_MACMDIOAR & MDIOAR_CR_MASK;
    ETH_MACMDIOAR = cr | (MDIOAR_GOC_READ << MDIOAR_GOC_SHIFT) |
                    (phy << MDIOAR_PA_SHIFT) | (reg << MDIOAR_RDA_SHIFT) |
                    MDIOAR_MB;
    mdio_wait();
    return (uint16_t)(ETH_MACMDIODR & 0xFFFFU);
}
```

Practical PHY-porting notes, all learned the hard way in the in-tree drivers:

- **Scan for the PHY address.** The PHY's MDIO address (0–31) is a strapping
  option; do not assume 0. Read the ID register at each address until you get a
  non-`0x0000`/non-`0xFFFF` value. The LPC driver retries the scan because some
  PHYs (LAN8742A) need the RMII clock stable before MDIO is reliable.
- **Match the MAC to the negotiated result.** After auto-negotiation completes,
  read the PHY's status/vendor register and program the MAC's speed (FES) and
  duplex (DM) bits to match. A duplex mismatch looks like "RX works, TX is
  silently dropped as collisions."
- **Some status bits are latched.** BMSR link-status latches low on link loss
  until read; the VA416xx driver double-reads to get the current state.

If you are on a simulator or a direct MAC-to-MAC link with no PHY, you can skip
all of this and force the MAC speed/duplex — but on real copper, PHY bring-up
is usually where the time goes.

### 4.9 Wiring the driver into the stack

The driver's init function fills the `wolfIP_ll_dev` and brings the hardware
up. Pattern from `lpc_enet_init()`:

```c
int lpc_enet_init(struct wolfIP_ll_dev *ll, const uint8_t *mac)
{
    if (!ll) return -1;

    memcpy(ll->mac, mac, 6);
    strncpy(ll->ifname, "eth0", sizeof(ll->ifname) - 1);
    ll->ifname[sizeof(ll->ifname) - 1] = '\0';
    ll->poll = eth_poll;        /* <- the two callbacks */
    ll->send = eth_send;

    mac_stop();
    if (hw_reset() != 0) return -2;
    mdio_init();
    config_mac(mac);
    config_mtl();
    config_dma();
    init_desc();                /* lay out the descriptor rings */
    phy_init();                 /* bring the PHY link up */
    config_speed_duplex();
    mac_start();                /* enable TX/RX, arm the RX ring */
    return 0;
}
```

The application then retrieves the device, points it at the driver, and sets
the IPv4 configuration (from the lwIP-migration guide's bare-metal pattern):

```c
wolfIP_init_static(&ipstack);
dev = wolfIP_getdev(ipstack);
lpc_enet_init(dev, my_mac);
wolfIP_ipconfig_set(ipstack,
    atoip4("192.168.1.50"), atoip4("255.255.255.0"), atoip4("192.168.1.1"));
```

You can fill the `wolfIP_ll_dev` fields in the init function (as above) or in
the caller after `wolfIP_getdev()` — both are used in-tree. For multiple
interfaces use `wolfIP_getdev_ex(s, idx)` and `wolfIP_ipconfig_set_ex()`.

### 4.10 Driver design checklist

- `poll` returns `>0` (one frame copied), `0` (nothing), or `<0` (error); it
  **never blocks**.
- `send` returns `≥0` (accepted) or `-WOLFIP_EAGAIN` (ring full); it never
  blocks and never drops the frame silently when full.
- `poll` clamps the copied length to the `len` the stack passed in.
- `send` pads short frames to the 60-byte Ethernet minimum.
- DMA: write the descriptor body before the OWN doorbell, with a barrier
  between, and kick the DMA tail pointer last.
- DMA on a cached core: `clean` before the MAC reads, `invalidate` before the
  CPU reads; align buffers to a cache line.
- Descriptors/buffers are static, aligned, and (if required) placed in
  DMA-reachable RAM.
- PHY address is discovered by scan; MAC speed/duplex follow the negotiated
  result.
- `ll->mac`, `ll->ifname`, `ll->mtu`, `ll->poll`, `ll->send` are all set before
  the first `wolfIP_poll()`.

---

## 5. Wiring a random-number source

Independently of the driver and OS, every port must provide one function the
stack calls for TCP initial sequence numbers, ephemeral ports, DNS IDs, and the
IP identification field (declared in `wolfip.h`):

```c
uint32_t wolfIP_getrandom(void);
```

Back it with a real entropy source — a hardware TRNG, a seeded DRBG, or
wolfCrypt's RNG. The POSIX port uses the OS (`src/port/posix/tap_linux.c`):

```c
uint32_t wolfIP_getrandom(void)
{
    uint32_t ret;
    getrandom(&ret, sizeof(ret), 0);
    return ret;
}
```

A wolfCrypt-backed version for products that already initialize wolfSSL:

```c
uint32_t wolfIP_getrandom(void)
{
    static WC_RNG rng;
    static int ready;
    uint32_t v = 0;
    if (!ready) { if (wc_InitRng(&rng) != 0) return 0; ready = 1; }
    wc_RNG_GenerateBlock(&rng, (byte *)&v, sizeof(v));
    return v;
}
```

Do **not** ship a constant, a bare timer value, or unseeded `rand()`:
predictable sequence numbers and ports are a security hole. Decide explicitly
how the function behaves if the entropy source fails.

---

## 6. Porting to a new operating system

On bare metal the "OS port" is one line: call `wolfIP_poll()` in `main()`'s
loop. Under an RTOS you usually want three more things:

- a **dedicated poll task** so the stack runs even while application tasks
  block;
- a **mutex** so application tasks and the poll task do not enter the
  single-threaded core concurrently;
- **blocking BSD sockets** so application code can write ordinary
  `recv()`/`send()` instead of polling for `-WOLFIP_EAGAIN`.

The FreeRTOS port (`src/port/freeRTOS/bsd_socket.c`) is the reference
implementation for all three; this section walks through building the
equivalent for a new RTOS, and section 7 shows a different shape (Zephyr's
socket-offload model) for contrast.

### 6.1 What an OS port has to provide

| Primitive | Used for |
|---|---|
| Mutex | Serialize every entry into the wolfIP core and `wolfIP_poll()`. |
| Binary semaphore / event per socket | Sleep a task until its socket is ready. |
| Task creation | Run the poll task. |
| Millisecond clock | Provide `now_ms` to `wolfIP_poll()`. |
| Sleep/delay | Idle the poll task between cycles. |

That is the whole dependency list. wolfIP needs no dynamic memory, no per-socket
threads, and no timer callbacks from the OS.

### 6.2 The poll task: the heartbeat of the stack

The poll task is a forever-loop that takes the core mutex, runs one poll cycle,
releases the mutex, and sleeps. `wolfIP_poll()` returns a hint for how many
milliseconds until the next timer is due; bound it so the task neither spins nor
oversleeps. The FreeRTOS version:

```c
static void wolfip_bsd_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;

    for (;;) {
        uint32_t next_ms;
        TickType_t delay_ticks;
        uint64_t now_ms = (uint64_t)xTaskGetTickCount() * (uint64_t)portTICK_PERIOD_MS;

        /* One poll cycle under the global lock so socket ops and timer
         * processing see a consistent core state. */
        xSemaphoreTake(g_lock, portMAX_DELAY);
        next_ms = (uint32_t)wolfIP_poll(ipstack, now_ms);
        xSemaphoreGive(g_lock);

        if (next_ms < WOLFIP_FREERTOS_POLL_MIN_MS) next_ms = WOLFIP_FREERTOS_POLL_MIN_MS;
        if (next_ms > WOLFIP_FREERTOS_POLL_MAX_MS) next_ms = WOLFIP_FREERTOS_POLL_MAX_MS;

        delay_ticks = pdMS_TO_TICKS(next_ms);
        if (delay_ticks == 0) delay_ticks = 1;   /* always yield at least 1 tick */
        vTaskDelay(delay_ticks);
    }
}
```

The default bounds are 5 ms minimum and 20 ms maximum. That floor stops the
task from busy-spinning; the ceiling guarantees TCP retransmit timers, delayed
ACKs, DHCP, and DNS still fire promptly. Lower the ceiling for latency, raise it
for power — but verify TCP behaviour after raising it.

### 6.3 The core mutex

wolfIP is single-threaded. The mutex is what lets a multi-tasking OS use it
safely: **every** call into `wolfIP_*` — from the poll task and from every
socket wrapper — happens while holding it. The FreeRTOS port creates one mutex
at init:

```c
g_lock = xSemaphoreCreateMutex();
```

The non-negotiable rule (section 8) is: hold the mutex *only* while inside the
core, and **never** hold it while blocking on a semaphore. Hold-while-sleeping
deadlocks the poll task and stalls the whole stack.

### 6.4 Building bsd_socket.c: the public FD table

Application tasks should not juggle wolfIP's internal socket descriptors
directly. The wrapper keeps a small table mapping a **public fd** (the small
integer it hands back from `socket()`/`accept()`) to the **internal wolfIP fd**
plus the per-socket wakeup primitive:

```c
typedef struct {
    int in_use;
    int internal_fd;                  /* the wolfIP_sock_* descriptor */
    SemaphoreHandle_t ready_sem;      /* given by the callback, taken by waiters */
    volatile uint16_t wait_events;    /* event bits this fd is blocked on */
    volatile uint16_t seen_events;    /* event bits the callback has delivered */
} wolfip_bsd_fd_entry;

static struct wolfIP *g_ipstack;
static SemaphoreHandle_t g_lock;
static wolfip_bsd_fd_entry g_fds[WOLFIP_FREERTOS_BSD_MAX_FDS];
```

`socket()` calls `wolfIP_sock_socket()` under the lock, then allocates a table
slot (and a fresh binary semaphore) for the returned internal fd:

```c
int socket(int domain, int type, int protocol)
{
    int ret, public_fd;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    ret = wolfIP_sock_socket(g_ipstack, domain, type, protocol);
    if (ret < 0) { wolfip_bsd_set_error(ret); xSemaphoreGive(g_lock); return -1; }
    public_fd = wolfip_bsd_fd_alloc(ret);          /* creates ready_sem */
    if (public_fd < 0) { wolfIP_sock_close(g_ipstack, ret); xSemaphoreGive(g_lock); return -1; }
    xSemaphoreGive(g_lock);
    return public_fd;
}
```

Non-blocking calls (`bind`, `listen`, `setsockopt`, `getsockname`, …) are
trivial: validate the fd, take the lock, call the matching `wolfIP_sock_*`,
release, translate a negative return to `-1`. The interesting ones are the
calls that can return `-WOLFIP_EAGAIN`.

### 6.5 Turning -WOLFIP_EAGAIN into blocking

wolfIP's socket calls never block — they return `-WOLFIP_EAGAIN` when an
operation would have to wait. The wrapper converts that into POSIX blocking
semantics with a lock / try / register-callback / unlock / wait / retry loop:

1. lock the core;
2. call the `wolfIP_sock_*` function;
3. success → unlock, return;
4. hard error → unlock, set errno, return `-1`;
5. `-WOLFIP_EAGAIN` → register a callback for the needed events, clear the
   semaphore, **unlock**, then block on the semaphore;
6. when the callback wakes the task, loop and retry.

Each blocking call waits on the event bits that make sense for it:

- `accept()` → `CB_EVENT_READABLE | CB_EVENT_CLOSED`
- `connect()` → `CB_EVENT_WRITABLE | CB_EVENT_CLOSED`
- `send()` → `CB_EVENT_WRITABLE | CB_EVENT_CLOSED`
- `recv()` → `CB_EVENT_READABLE | CB_EVENT_CLOSED`
- `close()` → `CB_EVENT_CLOSED` (only if close itself returns `-WOLFIP_EAGAIN`)

The "prepare wait" helper is the heart of the race-free hand-off. It must run
**while the core lock is held**, so a callback cannot fire between arming the
wait and registering for it:

```c
static void wolfip_bsd_prepare_wait_locked(wolfip_bsd_fd_entry *entry, uint16_t wait_events)
{
    entry->seen_events = 0;
    entry->wait_events = wait_events;
    while (xSemaphoreTake(entry->ready_sem, 0) == pdTRUE) { }   /* drain stale gives */
    wolfIP_register_callback(g_ipstack, entry->internal_fd, wolfip_bsd_socket_cb, entry);
}
```

### 6.6 Bridging wolfIP callbacks to OS wakeups

wolfIP delivers socket events by calling a registered callback from inside
`wolfIP_poll()` (i.e. from the poll task, with the lock already held). The
callback's only job is to record the events and wake any task waiting on those
bits. It must **not** do socket I/O and must **not** block:

```c
static void wolfip_bsd_socket_cb(int internal_fd, uint16_t events, void *arg)
{
    wolfip_bsd_fd_entry *entry = (wolfip_bsd_fd_entry *)arg;
    (void)internal_fd;
    if (entry == NULL) return;

    entry->seen_events |= events;
    if ((events & entry->wait_events) != 0)
        (void)xSemaphoreGive(entry->ready_sem);   /* wake the blocked task */
}
```

The `arg` you pass to `wolfIP_register_callback()` comes straight back here, so
pass the FD-table entry and you have O(1) access to the right semaphore.

### 6.7 A complete wrapper: recv()

Putting it together, here is the full blocking `recv()` — every other blocking
wrapper is the same skeleton with different event bits and a different
`wolfIP_sock_*` call:

```c
int recv(int sockfd, void *buf, size_t len, int flags)
{
    int ret;
    wolfip_bsd_fd_entry *entry;

    if (!wolfip_bsd_fd_valid(sockfd)) return -1;
    entry = &g_fds[sockfd];

    for (;;) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        ret = wolfIP_sock_recv(g_ipstack, entry->internal_fd, buf, len, flags);
        if (ret >= 0) {                              /* data, or 0 on close */
            xSemaphoreGive(g_lock);
            return ret;
        }
        if (ret != -WOLFIP_EAGAIN) {                 /* hard error */
            xSemaphoreGive(g_lock);
            wolfip_bsd_set_error(ret);
            return -1;
        }
        /* would block: arm the wait while still locked, then release+sleep */
        wolfip_bsd_prepare_wait_locked(entry,
            (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED));
        xSemaphoreGive(g_lock);
        if (wolfip_bsd_wait_unlocked(entry) < 0) {   /* block on ready_sem */
            wolfip_bsd_set_error(WOLFIP_EAGAIN);
            return -1;
        }
        /* woken: loop and retry wolfIP_sock_recv() */
    }
}
```

Trace the lock discipline: the core is locked around `wolfIP_sock_recv()` and
around `prepare_wait`, then **released before** `wait_unlocked()` blocks on the
semaphore. That is what lets the poll task keep running (and the callback fire)
while this task sleeps. `close()` additionally has to handle the TCP core
destroying the socket the instant it delivers `CB_EVENT_CLOSED` — see the
`seen_events & CB_EVENT_CLOSED` branch in the reference file.

### 6.8 Initialization and teardown

Init creates the mutex, clears the FD table, stores the stack pointer, and
spawns the poll task:

```c
int wolfip_freertos_socket_init(struct wolfIP *ipstack,
    UBaseType_t poll_task_priority, uint16_t poll_task_stack_words)
{
    if (ipstack == NULL) return -WOLFIP_EINVAL;
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) return -WOLFIP_ENOMEM;
    for (int i = 0; i < WOLFIP_FREERTOS_BSD_MAX_FDS; i++) g_fds[i].in_use = 0;
    g_ipstack = ipstack;
    if (xTaskCreate(wolfip_bsd_poll_task, "wolfip_poll", poll_task_stack_words,
            g_ipstack, poll_task_priority, NULL) != pdPASS) {
        vSemaphoreDelete(g_lock);
        return -WOLFIP_ENOMEM;
    }
    return 0;
}
```

On `close()`, clear the callback and free the table slot (deleting its
semaphore) under the lock so a concurrent callback never touches a freed entry:

```c
wolfIP_register_callback(g_ipstack, entry->internal_fd, NULL, NULL);
wolfip_bsd_fd_free(sockfd);          /* vSemaphoreDelete + mark slot free */
```

---

## 7. Case study: the Zephyr port

The Zephyr port (`port/zephyr/`) reaches the same destination as the FreeRTOS
wrapper — blocking BSD sockets backed by wolfIP — but through Zephyr's own
machinery, and it is worth studying because it shows the two structural pieces
of *any* OS port in a different idiom.

**The poll task** is the same heartbeat, written with Zephyr primitives. A
dedicated thread loops over `wolfIP_poll()` under a mutex and sleeps on a
semaphore with a timeout (`port/zephyr/patches/0001-wolfip-glue-and-public-api.patch`):

```c
static void wolfip_worker(void *arg1, void *arg2, void *arg3)
{
    while (true) {
        k_mutex_lock(&wolfip_ctx.lock, K_FOREVER);
        (void)wolfIP_poll(WOLFIP_STACK(), k_uptime_get());
        k_mutex_unlock(&wolfip_ctx.lock);

        (void)k_sem_take(&wolfip_ctx.wake_sem,
                         K_MSEC(CONFIG_WOLFIP_POLL_INTERVAL_MS));
    }
}
```

`k_mutex` is the core lock; `k_uptime_get()` is the millisecond clock; the
`wake_sem` with a timeout is the bounded sleep. Same three responsibilities as
section 6, different RTOS API.

**The driver surface** is where Zephyr differs most interestingly. Rather than a
bare-metal `wolfIP_ll_dev`, the port installs a thin **L2 module**
(`NET_L2_WOLFIP`) that overlays Zephyr's existing Ethernet driver. On receive it
linearises the `net_pkt` into a flat buffer and hands the whole raw frame to
wolfIP; on transmit it delegates to the underlying driver's `send` because
wolfIP has already built the Ethernet header
(`port/zephyr/patches/0002-net-l2-wolfip-module.patch`):

```c
static enum net_verdict wolfip_l2_recv(struct net_if *iface, struct net_pkt *pkt)
{
    ...
    if (net_pkt_read(pkt, frame, len) < 0) ...        /* linearise */
    wolfip_zephyr_l2_input(iface, frame, len);        /* hand raw frame up */
    ...
}

static int wolfip_l2_send(struct net_if *iface, struct net_pkt *pkt)
{
    ret = net_l2_send(api->send, net_if_get_device(iface), iface, pkt);
    ...
}
```

This is the same idea as `ll->poll`/`ll->send` — *"copy one complete raw
Ethernet frame in or out"* — expressed against Zephyr's driver model instead of
registers. The application then uses ordinary `socket()`/`recv()`/`send()` via
Zephyr's socket-offload framework, which the port backs with `wolfIP_sock_*`.

One wolfIP-specific subtlety the Zephyr port documents and that any
event-driven port should heed: wolfIP fires its socket callbacks from
`wolfIP_poll()`, and a listening socket processes one connection at a time. The
port therefore calls `wolfIP_poll()` synchronously after each received frame
and pre-accepts inside the listener callback, so a fast peer's final ACK does
not strand a half-open connection. If your OS port routes RX through an event
queue, make sure a poll cycle runs promptly after each frame.

---

## 8. RTOS locking rules

These rules apply to every OS port, FreeRTOS, Zephyr, or your own:

- Hold the core mutex while calling **any** `wolfIP_sock_*` function.
- Hold the core mutex while calling `wolfIP_poll()`.
- **Never** hold the core mutex while blocking on a semaphore/event — release
  it first, then wait.
- Keep wolfIP callbacks short: record events and wake a task, nothing more.
- Do not call a blocking socket wrapper from inside a wolfIP callback.
- Arm the wait (drain the semaphore, register the callback) **while locked**,
  so no event slips through between the failed call and the wait.
- Protect the public FD table consistently, and clear a socket's callback
  before freeing its table slot.
- Pick one error convention — BSD `-1` + errno, or raw wolfIP negatives — and
  apply it everywhere.

---

## 9. Porting checklist

**Driver**
- [ ] `poll`/`send` implemented per the section 4.1 contract; neither blocks.
- [ ] DMA: OWN-bit hand-off ordered with barriers; tail pointer kicked last.
- [ ] DMA on a cached core: clean-before-MAC-read, invalidate-before-CPU-read;
      buffers cache-line aligned and in DMA-reachable RAM.
- [ ] PHY discovered by MDIO scan; MAC speed/duplex follow negotiation.
- [ ] `mac`, `ifname`, `mtu`, `poll`, `send` set before first poll.

**Random**
- [ ] `wolfIP_getrandom()` backed by a real entropy source.

**Bare metal**
- [ ] `wolfIP_init_static()` / `wolfIP_init()` called; IP config set.
- [ ] `wolfIP_poll()` called in the main loop with a millisecond clock.

**RTOS**
- [ ] One poll task running `wolfIP_poll()` under the core mutex, bounded sleep.
- [ ] One core mutex around every core entry.
- [ ] Public FD table with one wakeup primitive per socket (if exposing BSD
      sockets).
- [ ] `-WOLFIP_EAGAIN` converted to wait-and-retry on the right event bits.
- [ ] Callbacks only wake tasks; never block while holding the lock.

---

## 10. Common porting pitfalls

**Blocking inside a driver callback.** `poll`/`send` run inline in
`wolfIP_poll()`. Returning `0`/`-WOLFIP_EAGAIN` is how you say "later"; a busy-
wait stalls the whole stack.

**Setting the DMA OWN bit before the buffer is visible.** Write the descriptor
body, barrier, *then* the OWN doorbell. Otherwise the MAC DMAs stale data.

**Forgetting cache maintenance on a cached core.** Without clean/invalidate the
CPU and MAC see different memory: TX sends stale bytes, RX reads stale OWN bits.
During bring-up, mark the DMA region non-cacheable to isolate this.

**Assuming the wrong descriptor variant.** Enhanced vs. normal Synopsys
descriptors put control bits in different words and wrap the ring differently.
Confirm against a known-good reference driver for your exact silicon.

**Assuming PHY address 0.** It is strapped per board; scan for it.

**Holding the core lock while sleeping.** The classic RTOS deadlock — the poll
task can never run to deliver the event you are waiting for. Unlock, then wait.

**Doing socket I/O in a callback.** Callbacks fire from `wolfIP_poll()` with the
lock held. Wake a task and let *it* do the I/O.

**Accepting only once per readable event.** A listener-readable event can cover
several pending connections; accept in a loop until `-WOLFIP_EAGAIN`.

**A weak `wolfIP_getrandom()`.** Predictable TCP sequence numbers and ephemeral
ports are a real vulnerability. Wire real entropy before shipping.

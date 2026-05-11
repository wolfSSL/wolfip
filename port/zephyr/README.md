# wolfIP port for Zephyr RTOS

This directory contains a set of patches that replace Zephyr's native
IPv4/TCP/UDP/ARP/ICMP/DHCPv4 stack with [wolfIP](https://github.com/wolfSSL/wolfIP)
on a per-interface basis. The patches are maintained out-of-tree.

After applying the patches, any Zephyr application that uses BSD sockets
through `CONFIG_NET_SOCKETS` will transparently route its traffic through
wolfIP. ARP, ICMP, IPv4 routing, and (optional) DHCPv4 are also owned by
wolfIP rather than Zephyr.

The port has been developed and verified against **Zephyr v4.4.0**.

---

## Table of contents

1. [Design overview](#design-overview)
2. [Repository layout](#repository-layout)
3. [Prerequisites](#prerequisites)
4. [Quick start](#quick-start)
5. [The patches in detail](#the-patches-in-detail)
6. [Application configuration](#application-configuration)
7. [Sample: `wolfip_tap_echo`](#sample-wolfip_tap_echo)
8. [Building for a hardware target](#building-for-a-hardware-target)
9. [Net-shell commands](#net-shell-commands)
10. [API reference](#api-reference)
11. [Known limitations](#known-limitations)
12. [Maintenance notes](#maintenance-notes)
13. [Troubleshooting](#troubleshooting)

---

## Design overview

### The problem with Zephyr's native stack

Zephyr's networking subsystem assumes its native L3+ (IPv4, IPv6, TCP, UDP,
ICMP) implementations own each interface. The `struct net_if_dev` carries
the IPv4 configuration, the ARP cache lives inside the Ethernet L2 module
in `subsys/net/l2/ethernet/`, and the per-protocol dispatch happens in
`subsys/net/ip/net_core.c::process_data()` after L2 demux. Bolting wolfIP
on top by diverting *after* L2 processing has structural problems:

- Zephyr's ARP consumes ARP frames before any L2-divert hook fires,
  so wolfIP never learns the peer MAC and can never reply.
- The Ethernet header is stripped by `net_buf_pull(pkt->frags, hdr_len)`
  inside `ethernet_recv()` before any post-L2 hook runs, so wolfIP — which
  expects raw Ethernet frames — would parse the IP header as if it were
  the L2 header.
- Two stacks end up owning the same MAC: ambiguous, racy, and a
  debugging nightmare.

### The fix: wolfIP owns the interface end-to-end

This port introduces **`NET_L2_WOLFIP`** — a thin L2 module under
`subsys/net/l2/wolfip/` that, on `recv`, linearises the frame and hands
the full raw bytes (Ethernet header included) to `wolfip_zephyr_l2_input`;
on `send`, it calls the underlying Ethernet driver's `api->send` directly
because wolfIP has already built the L2 header.

Attaching wolfIP to a Zephyr interface (`wolfip_attach_iface()`) performs
a one-time runtime swap of the interface's L2 pointer:

```c
const struct net_l2 **l2_ptr = (const struct net_l2 **)&iface->if_dev->l2;
*l2_ptr = &NET_L2_GET_NAME(WOLFIP_L2);
```

Yes, this casts away `const`. Zephyr offers no public runtime-L2-swap
API, and `iface->if_dev->l2` is declared `const struct net_l2 * const`.
Since the pointer is read at runtime via dereference (the compiler cannot
constant-fold it), the cast is practically safe.

After the swap, every frame on this interface routes:

```
eth driver  →  NET_L2_WOLFIP.recv  →  wolfip_zephyr_l2_input  →
wolfIP_recv_ex  →  wolfIP_poll  →  socket-offload callback / event
```

…and socket calls from the application (`socket()`, `bind()`, `connect()`,
`send()`, `recv()`, `close()`, etc.) route through Zephyr's existing
socket-offload mechanism into `wolfip_socket_fd_op_vtable`.

### Why the L2 calls `wolfIP_poll` synchronously between frames

wolfIP fires its registered socket callbacks from `wolfIP_poll`'s
"step 3" loop, not from `wolfIP_recv_ex` itself. wolfIP's listener
design is deliberately sequential: when a SYN arrives the listener
itself becomes the SYN_RCVD socket for the in-flight connection. If
the listener's callback fires only on a periodic timer tick, the peer's
final ACK (and possibly data + FIN in a fast LAN) can land before the
application's `accept()` runs, stranding the connection in ESTABLISHED
or CLOSE_WAIT before wolfIP can hand it off to a fresh socket. The
port works around this by calling `wolfIP_poll` synchronously after
every `wolfIP_recv_ex`, and by pre-accepting in the listener callback
(see `wolfip_socket_event_cb` in `wolfip_zephyr.c`).

### What is *not* affected

- Zephyr's net_if infrastructure, net_pkt allocator, the Ethernet
  driver model, NET_NATIVE, NET_MGMT events, and the socket-offload
  framework are all kept enabled. The port only **disables** the L3+
  symbols (`NET_IPV4`, `NET_TCP`, `NET_UDP`, `NET_ARP`, `NET_DHCPV4`,
  …) — the rest of the network subsystem still drives the driver and
  serves BSD sockets.
- IPv6 is out of scope and untouched.

---

## Repository layout

```
wolfip/
├── port/
│   └── zephyr/
│       ├── README.md                         <-- you are here
│       └── patches/
│           ├── 0001-wolfip-glue-and-public-api.patch
│           ├── 0002-net-l2-wolfip-module.patch
│           ├── 0003-net-shell-wolfip.patch
│           └── 0004-sample-wolfip-tap-echo.patch
└── src/
    └── wolfip.c          (the wolfIP stack itself, unchanged by these patches)
```

The patches are applied **into a Zephyr v4.4.0 checkout**, not into wolfIP.
The Zephyr-side build wires wolfIP into its library tree via
`add_subdirectory_ifdef(CONFIG_WOLFIP wolfip)` and expects the wolfIP
source tree to live next to the Zephyr tree on disk (see
[Quick start](#quick-start)).

---

## Prerequisites

| Component | Tested version | Notes |
|---|---|---|
| Zephyr RTOS | v4.4.0 | The patches assume this exact tree. |
| Zephyr SDK / toolchain | matched to your board | `native_sim` only needs host gcc. |
| west | ≥ 0.14 | for `west build`. |
| wolfIP | tip of `master` at port time | Lives next to the Zephyr tree. |
| net-tools | from Zephyr | Provides `net-setup.sh` / `zeth.conf` for TAP testing. |

For the `native_sim` sample you also need:

- Linux with `CAP_NET_ADMIN` (or `sudo`) to bring up the `zeth` TAP
- `iproute2`, `nc`/`ncat`, `ping` (for end-to-end testing)

---

## Quick start

This walks through bringing up the sample on `native_sim` from scratch.

### 1. Layout the source trees

The patches assume this directory layout:

```
<workspace>/
├── wolfip/             <-- this repo
└── zephyr-v4.4.0/      <-- a clean Zephyr v4.4.0 west workspace
    └── zephyr/         <-- the Zephyr tree itself
```

The wolfIP integration library's CMakeLists hard-codes the wolfIP
source path as `${ZEPHYR_BASE}/../../wolfip`. If your layout differs
either symlink it or edit
`subsys/net/lib/wolfip/CMakeLists.txt:5` after applying the patches.

```bash
mkdir -p ~/src && cd ~/src
git clone https://github.com/wolfSSL/wolfIP.git wolfip

# Zephyr v4.4.0 — use west init OR git directly
mkdir zephyr-v4.4.0 && cd zephyr-v4.4.0
west init -m https://github.com/zephyrproject-rtos/zephyr --mr v4.4.0
west update
```

### 2. Apply the patches

```bash
cd ~/src/zephyr-v4.4.0/zephyr
for p in ~/src/wolfip/port/zephyr/patches/*.patch; do
    git apply --whitespace=nowarn "$p" || exit 1
done
```

Apply order matters: 0001 → 0002 → 0003 → 0004. The numbering is
significant — 0002 references symbols declared by 0001, etc.

If you prefer `git am` you can pipe each patch through it; the
`Subject:` line at the top of each patch is `git am`-compatible.

### 3. Build the sample

```bash
cd ~/src/zephyr-v4.4.0/zephyr
source ../.venv/bin/activate     # or however you activate west's venv
west build -b native_sim -p auto samples/net/sockets/wolfip_tap_echo
```

### 4. Set up the TAP interface

Zephyr's `net-tools` provides `net-setup.sh` which creates a `zeth`
TAP at `192.0.2.2/24`. The sample binds to `192.0.2.1/24` on the
Zephyr side.

```bash
# In a separate terminal, from the zephyr/net-tools clone:
sudo ./net-setup.sh
# Confirm:
ip addr show zeth
#   inet 192.0.2.2/24 brd 192.0.2.255 scope global zeth
```

### 5. Run the binary

```bash
./build/zephyr/zephyr.exe --eth-if=zeth
```

You should see:

```
*** Booting Zephyr OS build v4.4.0 ***
<inf> wolfip_tap_echo: wolfIP enabled on iface 1
<inf> wolfip_tap_echo: wolfIP: configured 192.0.2.1/255.255.255.0 gw 192.0.2.2
<inf> wolfip_tap_echo: TCP echo listening on 192.0.2.1:4242
<inf> wolfip_tap_echo: UDP echo listening on 192.0.2.1:4242
uart connected to pseudotty: /dev/pts/N
```

### 6. Test end-to-end

```bash
# ICMP
ping -c 3 192.0.2.1

# UDP echo
echo "hello-udp" | nc -u -w 1 192.0.2.1 4242

# TCP echo
echo "hello-tcp" | nc -q 1 192.0.2.1 4242

# Net shell — connect to the pseudotty path printed above
screen /dev/pts/N    # or `cu`, `picocom`, `socat`, …
uart:~$ net iface
uart:~$ net ipv4
uart:~$ net arp lookup 1 192.0.2.2
uart:~$ net ping -c 3 192.0.2.2
```

If all four work, the port is functioning correctly.

---

## The patches in detail

Each patch is a `git diff`-format unified diff with a `Subject:` header
and a short rationale at the top. They apply in numeric order and each
builds on the previous one.

### `0001-wolfip-glue-and-public-api.patch`

The wolfIP runtime glue, control wrapper API, and public header.
This patch alone gives you a buildable but functionally-inactive
wolfIP runtime — `CONFIG_WOLFIP=y` becomes selectable and the
library compiles, but no interface is yet bound.

Adds:

| Path | Purpose |
|---|---|
| `include/zephyr/net/wolfip.h` | Public API — iface attach/detach, `wolfip_ctrl_*` wrappers, accessors. Forward-declares `ip4`, `struct wolfIP`, `struct wolfIP_route_info` so callers needn't include the wolfIP source-tree header. |
| `subsys/net/lib/wolfip/wolfip_zephyr.c` | The integration runtime. Owns the wolfIP stack instance, the worker thread that drives `wolfIP_poll` on a timer, the socket-offload vtable (`socket`/`bind`/`connect`/…/`close` + ioctl/poll prepare/update), DNS offload, and the `wolfip_attach_iface` / `wolfip_detach_iface` / `wolfip_zephyr_l2_input` entrypoints used by patches 2/3/4. |
| `subsys/net/lib/wolfip/wolfip_control.c` | Thin wrappers around the wolfIP public API (`wolfIP_ipconfig_get/set_ex`, `wolfIP_arp_lookup_ex`, `wolfIP_route_*`, `dhcp_client_init`, etc.). Each wrapper takes the wolfIP lock and returns 0/negative-errno. Consumers in the shell call these instead of the wolfIP source-tree symbols directly. |
| `subsys/net/lib/wolfip/Kconfig` | The `menuconfig WOLFIP` symbol with its dependencies (`NETWORKING`, `NET_SOCKETS`) and selects (`NET_SOCKETS_OFFLOAD`, `NET_L2_WOLFIP`), plus tuning knobs for the worker stack/priority/interval and wolfIP instance storage. |
| `subsys/net/lib/wolfip/CMakeLists.txt` | Compiles the integration library, exposes `${WOLFIP_ROOT}` as an include directory, and pulls in `${WOLFIP_ROOT}/src/wolfip.c` itself. |

Modifies:

| Path | Change |
|---|---|
| `subsys/net/lib/CMakeLists.txt` | `add_subdirectory_ifdef(CONFIG_WOLFIP wolfip)` |
| `subsys/net/lib/Kconfig` | `source "subsys/net/lib/wolfip/Kconfig"` |

### `0002-net-l2-wolfip-module.patch`

The new `NET_L2_WOLFIP` L2 module. With this applied and
`CONFIG_NET_L2_WOLFIP=y`, the L2 layer is registered with the kernel,
and `wolfip_attach_iface` can swap it onto an interface.

Adds:

| Path | Purpose |
|---|---|
| `subsys/net/l2/wolfip/wolfip_l2.c` | The four L2 ops — `recv` (linearise, hand to `wolfip_zephyr_l2_input`, unref), `send` (delegate to `net_l2_send(api->send, …)`), `enable` (forward to the eth driver `start`/`stop`), and `flags` (returns `NET_L2_MULTICAST \| NET_L2_PROMISC_MODE`). Registers via `NET_L2_INIT(WOLFIP_L2, …)`. |
| `subsys/net/l2/wolfip/Kconfig` | `config NET_L2_WOLFIP` — depends on `WOLFIP`. |
| `subsys/net/l2/wolfip/CMakeLists.txt` | Module build. |

Modifies:

| Path | Change |
|---|---|
| `subsys/net/l2/CMakeLists.txt` | `if(CONFIG_NET_L2_WOLFIP) add_subdirectory(wolfip) endif()` |
| `subsys/net/l2/Kconfig` | `source "subsys/net/l2/wolfip/Kconfig"` |

### `0003-net-shell-wolfip.patch`

Makes the `net` shell tree wolfIP-aware. Two parts:

1. **Kconfig umbrella amendments** in `subsys/net/lib/shell/Kconfig` —
   every `NET_SHELL_*_SUPPORTED` symbol that previously keyed off
   `NET_IPV4` / `NET_TCP` / `NET_UDP` / `NET_DHCPV4` / `NET_ROUTE` /
   `NET_IP` now also accepts `WOLFIP`. Without this, the shell command
   files would not even be compiled in a wolfIP-only build.

2. **Per-file rewrites**, each adding an `#elif defined(CONFIG_WOLFIP)`
   branch alongside the existing `#if defined(CONFIG_NET_…)` native
   branch, so the native paths remain compilable for users who
   keep Zephyr's stack:

   | File | Commands affected | Backend used |
   |---|---|---|
   | `iface.c` | IPv4 + DHCPv4 print blocks in `net iface` | `wolfip_ctrl_get_addr`, `wolfip_ctrl_dhcp_is_running/is_bound` |
   | `ipv4.c` | `net ipv4`, `net ipv4 add/del/gateway` | `wolfip_ctrl_get_addr` / `set_addr` |
   | `arp.c` | `net arp`, `net arp lookup`, `net arp flush`, `net arp add` | `wolfip_ctrl_arp_lookup`; flush/add stubbed as "not supported" |
   | `ping.c` | `net ping <ipv4>` | BSD `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` via the wolfIP offload |
   | `route.c` | `net route add/del`, `net route` dump | `wolfip_ctrl_route_add/del/count/get` |
   | `dhcpv4.c` | `net dhcpv4 client start/stop/status` | `wolfip_ctrl_dhcp_start/is_running/is_bound`; server stubbed |
   | `tcp.c` | `net tcp connect/send/recv/close` | BSD sockets |
   | `udp.c` | `net udp bind/send/recv/close` | BSD sockets |
   | `conn.c` | Guards tightened so undefined refs (`net_conn_foreach`, etc.) skip cleanly | n/a |
   | `stats.c` | Native-counter blocks gated more tightly | n/a |

### `0004-sample-wolfip-tap-echo.patch`

A minimal sample under `samples/net/sockets/wolfip_tap_echo/`:

| File | Purpose |
|---|---|
| `src/main.c` | Brings the interface up via `wolfip_enable_iface`, sets `192.0.2.1/24 gw 192.0.2.2` via `wolfip_ctrl_set_addr`, then spawns two threads each running a textbook BSD-socket echo loop (TCP and UDP on port 4242). |
| `prj.conf` | `CONFIG_WOLFIP=y`, `CONFIG_NET_L2_WOLFIP=y`, `CONFIG_ETH_NATIVE_TAP=y`, `CONFIG_NET_SOCKETS=y`, `CONFIG_POSIX_API=y`, `CONFIG_SHELL=y`, `CONFIG_NET_SHELL=y`. **No** `CONFIG_NET_IPV4` / `NET_TCP` / `NET_UDP` / `NET_CONFIG_*`. |
| `boards/native_sim.conf` | Board-specific tuning (TAP driver, stack sizes). |
| `CMakeLists.txt`, `sample.yaml`, `README.rst` | Standard Zephyr sample plumbing. |

---

## Application configuration

For any application that wants to use wolfIP instead of Zephyr's native
stack, the `prj.conf` skeleton looks like this:

```kconfig
# Networking core
CONFIG_NETWORKING=y
CONFIG_NET_SOCKETS=y
CONFIG_POSIX_API=y

# Zephyr native IPv4/TCP/UDP are off — wolfIP owns the L3+ stack.
CONFIG_NET_IPV6=n

# L2 stack
CONFIG_NET_L2_ETHERNET=y    # driver model requirement
CONFIG_NET_L2_WOLFIP=y      # intercepts raw frames

# wolfIP
CONFIG_WOLFIP=y
CONFIG_WOLFIP_DHCPV4=n
CONFIG_WOLFIP_MAX_INTERFACES=1

# Net packet buffers (still used for raw L2 frames)
CONFIG_NET_PKT_RX_COUNT=24
CONFIG_NET_PKT_TX_COUNT=24
CONFIG_NET_BUF_RX_COUNT=96
CONFIG_NET_BUF_TX_COUNT=96

# Sockets
CONFIG_ZVFS_OPEN_MAX=32
```

**Do not enable** `CONFIG_NET_IPV4`, `CONFIG_NET_TCP`, `CONFIG_NET_UDP`,
`CONFIG_NET_ARP`, `CONFIG_NET_DHCPV4`, or `CONFIG_NET_CONFIG_SETTINGS`.
The `WOLFIP` Kconfig does **not** depend on `NET_IPV4` — it is
specifically designed to be used **instead** of the native stack.

### Bringing the interface up in your application

```c
#include <zephyr/net/wolfip.h>
#include <zephyr/net/net_if.h>

int main(void)
{
    struct net_if *iface = net_if_get_default();
    unsigned int if_idx;
    struct in_addr ip, mask, gw;

    /* This (a) marks iface as wolfIP-owned, (b) swaps L2 to NET_L2_WOLFIP,
     * (c) registers the socket offload, (d) brings the iface admin-up. */
    wolfip_enable_iface(iface);

    /* Map Zephyr's net_if index to wolfIP's if_idx, then configure
     * the IPv4 address.  IP arithmetic uses wolfIP's host-order ip4 type. */
    wolfip_zephyr_get_if_idx(iface, &if_idx);

    net_addr_pton(AF_INET, "192.0.2.1",   &ip);
    net_addr_pton(AF_INET, "255.255.255.0", &mask);
    net_addr_pton(AF_INET, "192.0.2.2",   &gw);

    wolfip_ctrl_set_addr(if_idx,
                          sys_be32_to_cpu(ip.s_addr),
                          sys_be32_to_cpu(mask.s_addr),
                          sys_be32_to_cpu(gw.s_addr));

    /* From this point on, plain POSIX BSD sockets work: */
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    /* … */
}
```

If you prefer DHCPv4 instead of static configuration, set
`CONFIG_WOLFIP_DHCPV4=y` and call `wolfip_ctrl_dhcp_start(if_idx)`
after `wolfip_enable_iface`.

---

## Sample: `wolfip_tap_echo`

The sample lives at `samples/net/sockets/wolfip_tap_echo/`. It:

- attaches wolfIP to the default interface (the `eth_native_tap` driver)
- configures `192.0.2.1/24 gw 192.0.2.2`
- runs a TCP echo on port 4242
- runs a UDP echo on port 4242
- enables the `net` shell on the pseudo-tty

### Running

```bash
# Terminal 1 — host network setup (once per session)
sudo ip link add zeth type tuntap mode tap
sudo ip addr add 192.0.2.2/24 dev zeth
sudo ip link set zeth up
# (or just use net-tools/net-setup.sh from Zephyr if you have it)

# Terminal 2 — the sample
cd ~/src/zephyr-v4.4.0/zephyr
west build -b native_sim -p auto samples/net/sockets/wolfip_tap_echo
./build/zephyr/zephyr.exe --eth-if=zeth --mac-addr=02:00:5e:00:53:61

# Terminal 3 — testing
ping -c 3 192.0.2.1
echo "x" | nc -u -w 1 192.0.2.1 4242
echo "y" | nc -q 1 192.0.2.1 4242
```

The `--mac-addr=…` argument is optional but recommended — without it
the simulator picks a random MAC each boot, which means the host kernel's
ARP cache for `192.0.2.1` may go stale between runs.

### Sample-specific configuration

If you change the addresses, edit the `SAMPLE_LOCAL_IPV4` /
`SAMPLE_LOCAL_NETMASK` / `SAMPLE_LOCAL_GW` macros at the top of
`samples/net/sockets/wolfip_tap_echo/src/main.c`. They are passed
directly to `wolfip_ctrl_set_addr` at boot.

---

## Building for a hardware target

The sample uses `native_sim` with the TAP driver, but the wolfIP port
itself is driver-agnostic — `NET_L2_WOLFIP` overlays any Ethernet
driver that registers via `ETHERNET_L2`. To run on real hardware:

1. Pick a board with an Ethernet driver (e.g. `frdm_k64f`,
   `nucleo_h743zi`, `mimxrt1064_evk`, …).
2. Use the same `prj.conf` skeleton from the sample. Adjust the
   `_MAX_INTERFACES`, stack sizes, and DHCPv4 settings as needed.
3. `west build -b <board> samples/net/sockets/wolfip_tap_echo`.
4. Flash and connect a serial console to access the shell.

The port has not been formally regression-tested on hardware — please
report issues you hit.

---

## Net-shell commands

After `CONFIG_NET_SHELL=y`, the standard `net` command tree is wired
into wolfIP:

| Command | Action |
|---|---|
| `net iface` | Per-interface report with IPv4 (wolfIP) and DHCPv4 (wolfIP) blocks. |
| `net ipv4` | Top-level IPv4 summary, plus per-iface table. |
| `net ipv4 add <iface> <addr> [<mask>]` | Configure address on a wolfIP interface. |
| `net ipv4 del <iface> <addr>` | Clear the address (wolfIP stores one per iface). |
| `net ipv4 gateway <iface> <gw>` | Set default gateway. |
| `net arp lookup <iface> <ip>` | One-shot ARP resolution; prints `ip -> MAC` or `no ARP entry`. |
| `net route` | Dump wolfIP routing table. |
| `net route add <iface> <prefix>[/<plen>] <gw>` | Add a static route. |
| `net route del <iface> <prefix>[/<plen>]` | Remove a static route. |
| `net dhcpv4 client start <iface>` | Start the wolfIP DHCPv4 client. |
| `net dhcpv4 client status <iface>` | Reports `bound` / `running` / `idle`. |
| `net ping [-c N] [-i ms] <addr>` | ICMP echo via a wolfIP ICMP socket. |
| `net tcp connect <ip> <port>` | Open a TCP client connection. |
| `net tcp send <data>` | Send a string on the open TCP connection. |
| `net tcp recv` | Non-blocking receive on the open TCP connection. |
| `net tcp close` | Close the TCP connection. |
| `net udp bind <ip\|any> <port>` | Bind a UDP socket. |
| `net udp send <ip> <port> <data>` | Send a datagram. |
| `net udp recv` | Non-blocking receive on the bound UDP socket. |
| `net udp close` | Close the UDP socket. |

Commands not in the wolfIP world (DHCPv4 server, IGMP join, static
ARP add, ARP cache flush/iterate) print a clear `"not supported"`
message rather than silently no-op'ing.

---

## API reference

All declarations live in `<zephyr/net/wolfip.h>`. The control wrapper
implementations live in `subsys/net/lib/wolfip/wolfip_control.c` and
the integration glue in `wolfip_zephyr.c`.

### Interface management

```c
int  wolfip_enable_iface(struct net_if *iface);
int  wolfip_disable_iface(struct net_if *iface);
bool wolfip_iface_is_enabled(struct net_if *iface);
int  wolfip_attach_iface(struct net_if *iface);    /* alias for enable */
int  wolfip_detach_iface(struct net_if *iface);    /* alias for disable */
int  wolfip_zephyr_get_if_idx(struct net_if *iface, unsigned int *if_idx);
```

### Stack/lock accessors (advanced)

```c
struct wolfIP *wolfip_zephyr_get_stack(void);
void           wolfip_zephyr_lock(void);
void           wolfip_zephyr_unlock(void);
```

Use the lock if you call wolfIP source-tree APIs directly — every
`wolfip_ctrl_*` wrapper already takes it internally.

### IPv4 / ARP / route / DHCP wrappers

```c
int wolfip_ctrl_get_addr(unsigned int if_idx, ip4 *ip, ip4 *mask, ip4 *gw);
int wolfip_ctrl_set_addr(unsigned int if_idx, ip4 ip, ip4 mask, ip4 gw);

int wolfip_ctrl_dhcp_start(unsigned int if_idx);
int wolfip_ctrl_dhcp_is_running(unsigned int if_idx);
int wolfip_ctrl_dhcp_is_bound(unsigned int if_idx);

int wolfip_ctrl_get_dns(ip4 *dns);
int wolfip_ctrl_arp_lookup(unsigned int if_idx, ip4 ip, uint8_t mac_out[6]);

int          wolfip_ctrl_route_add(unsigned int if_idx, ip4 prefix, uint8_t plen, ip4 gw);
int          wolfip_ctrl_route_del(unsigned int if_idx, ip4 prefix, uint8_t plen);
unsigned int wolfip_ctrl_route_count(void);
int          wolfip_ctrl_route_get(unsigned int idx, struct wolfIP_route_info *info_out);
```

All wrappers return 0 on success and a negative errno on failure.
`ip4` is `uint32_t` in host byte order, MSB first (i.e.
`192.0.2.1 == 0xC0000201`).

### Internal L2 hook

```c
int wolfip_zephyr_l2_input(struct net_if *iface, const uint8_t *frame, size_t len);
```

Called only by `subsys/net/l2/wolfip/wolfip_l2.c`. Not for application use.

---

## Known limitations

- **No IGMP / multicast group management** — wolfIP exposes no public
  API for joining/leaving groups, so `net ipv4 add … join` returns
  "not supported".
- **No DHCPv4 server** — wolfIP is client-only on DHCPv4.
- **No DHCPv4 client stop** — wolfIP has no `dhcp_client_stop` entry
  point; `net dhcpv4 client stop` prints "not supported".
- **No ARP cache iteration / flush / static add** — `net arp` and
  `net arp flush` / `net arp add` are stubbed accordingly. Only
  `net arp lookup` works.
- **No per-iface DHCPv4** — `dhcp_client_init` is a stack-wide
  function. `wolfip_ctrl_dhcp_start` accepts an `if_idx` for API
  symmetry but currently ignores it beyond bounds-checking.
- **Single in-flight TCP accept** — by wolfIP design, a listening
  socket processes one connection at a time. New SYNs arriving while
  another handshake is in progress are dropped (DoS protection). The
  integration layer pre-accepts inline from the RX callback to keep
  this window as small as one `wolfIP_recv_ex` invocation, but bursty
  load can still drop SYNs that would have been queued in a
  conventional accept-queue stack.
- **Net statistics counters** are not exposed by wolfIP. `net stats`
  prints a `wolfIP statistics: not exposed.` placeholder.
- **IPv6 is out of scope** — neither the L2 module nor any of the
  shell rewrites touch IPv6. If your application needs both, you must
  run with Zephyr's native IPv6 alongside wolfIP's IPv4 (untested
  configuration).
- **`const` L2 swap is a controlled hack** — see the [Design
  overview](#design-overview). Should Zephyr ever introduce a real
  runtime-L2-swap API the cast can be removed; for now the cast is
  the only practical mechanism.

---

## Maintenance notes

### Patch organisation rationale

Patches are split by **subsystem boundary** rather than by code change
size, so a future maintainer can rebase one onto a new Zephyr release
without dragging unrelated areas along:

- 0001 owns the wolfIP integration core. Touches only
  `include/zephyr/net/wolfip.h` and `subsys/net/lib/wolfip/`, plus two
  one-line additions in the parent net/lib build tree.
- 0002 owns the L2 module. Touches only `subsys/net/l2/wolfip/` plus
  two one-line additions in the parent net/l2 build tree.
- 0003 owns the net-shell rewrites. Touches only
  `subsys/net/lib/shell/`. This is the most upstream-volatile patch:
  shell command files churn between Zephyr releases.
- 0004 owns the demo app under `samples/`. Touches nothing else.

### Refreshing the patches against a newer Zephyr

When porting to a newer Zephyr release:

1. Try `git apply --3way <patch>` first — three-way merge handles
   most context drift.
2. If `--3way` fails, apply manually and regenerate the patch with
   `git diff > <newpatch>`.
3. Run the sample's end-to-end test (see [Quick start](#quick-start)
   step 6) before declaring the refresh done.
4. Patch 0003 is the most likely to break — Zephyr's shell command
   files get reformatted and reorganised relatively often. The
   amendments are mechanical (`#elif defined(CONFIG_WOLFIP)`
   branches); diff carefully against the new upstream version.

### Reading the diffs

All four patches are produced by `git diff --cached`, so they apply
with either `git apply` or `patch -p1`. They are *not* `git
format-patch` output and do not carry author / date metadata — they
are plain unified diffs with a short rationale at the top.

### Code locations to know

| File | Role |
|---|---|
| `subsys/net/lib/wolfip/wolfip_zephyr.c::wolfip_socket_event_cb` | The pre-accept inline that closes the SYN_RCVD race. Touch this if multi-connection TCP regresses. |
| `subsys/net/lib/wolfip/wolfip_zephyr.c::wolfip_zephyr_l2_input` | Calls `wolfIP_poll` synchronously. Touch this if performance is a concern (poll is currently per-frame). |
| `subsys/net/lib/wolfip/wolfip_zephyr.c::wolfip_attach_iface` | The L2 swap (`*l2_ptr = &NET_L2_GET_NAME(WOLFIP_L2);`). The `const`-cast is here. |
| `subsys/net/lib/wolfip/wolfip_zephyr.c::wolfip_is_supported_family` | Whitelist of protocols accepted by the offload socket — TCP/UDP/ICMP/0. Extend if you add new protocol support. |
| `subsys/net/l2/wolfip/wolfip_l2.c::wolfip_l2_recv` | Linearises the frame into a stack buffer. Stack-buffer size (1600 B) caps the per-frame size. |

---

## Troubleshooting

### `west build` fails with `WOLFIP depends on NET_IPV4` or similar

You are not at the right Zephyr version, or you are applying these
patches on top of an older snapshot where `WOLFIP` was experimentally
gated on `NET_IPV4`. Patch 0001 explicitly removes that dependency
and replaces it with `depends on NETWORKING`. Re-check that 0001
applied cleanly.

### `Cannot create zeth (-16/Device or resource busy)` at boot

A previous instance of the binary is still holding the TAP. `pkill
-9 zephyr.exe` and retry.

### `ping 192.0.2.1` works but TCP/UDP echo to port 4242 silently times out

The host kernel cached a stale MAC for `192.0.2.1` from a previous
run. `ip neigh del 192.0.2.1 dev zeth` and retry. Or pass
`--mac-addr=02:00:5e:00:53:61` to the simulator so the MAC is
stable across boots.

### `net ping` returns immediately with no replies

Verify that `wolfip_is_supported_family` in `wolfip_zephyr.c`
accepts `IPPROTO_ICMP`. The patch enables it; if you've cherry-picked
parts of 0001 you may have dropped this. Grep:

```
grep IPPROTO_ICMP subsys/net/lib/wolfip/wolfip_zephyr.c
```

### Multi-connection TCP misbehaves under load

Increase `MAX_TCPSOCKETS` in `wolfip/config.h` (default 4). Note
that wolfIP processes incoming connections strictly serially; bursty
clients sending many SYNs at once will see some get dropped. The
correct mitigation is on the client side (back-off + retry); changing
wolfIP's listener semantics is out of scope of this port.

### `net iface` shows the interface but `Flags` does not list `IPv4`

`wolfip_attach_iface` calls `net_if_flag_set(iface, NET_IF_IPV4)`. If
you see no `IPv4` flag, the iface attach didn't happen — confirm
`wolfip_enable_iface(iface)` was called from your app's `main`.

---

## License

The wolfIP runtime and these Zephyr-port patches are licensed under
GPLv3. Zephyr itself is Apache-2.0. Because the patches modify
Apache-2.0 files in-place, applying them produces a derivative work;
distribute the patched Zephyr tree under GPLv3 if you redistribute.
The patches as standalone files in this repository are GPLv3.

# wolfGuard How-To

This guide shows how to use the wolfIP **wolfGuard** module (`src/wolfguard/`):
a FIPS-compliant implementation of the WireGuard VPN protocol that runs entirely
inside the wolfIP stack. It covers how to build it, how to provision keys and
peers, how a tunnel is established, how traffic flows through it, and how to
interoperate with the Linux kernel wolfGuard module for testing.

It is a getting-started document, not a reference manual. The authoritative API
is `src/wolfguard/wolfguard.h`; the worked examples come from
`src/test/test_wolfguard_loopback.c` (two wolfIP stacks back-to-back) and
`src/test/test_wolfguard_interop.c` plus
`tools/scripts/test-interop-wolfguard.sh` (wolfIP against the kernel module).

## Table of Contents

- [1. What wolfGuard is](#1-what-wolfguard-is)
- [2. Building with wolfGuard](#2-building-with-wolfguard)
- [3. Mental model: the wg0 interface and the data path](#3-mental-model-the-wg0-interface-and-the-data-path)
- [4. The public API](#4-the-public-api)
- [5. Keys, peers and allowed IPs](#5-keys-peers-and-allowed-ips)
- [6. Step by step: bringing up a tunnel](#6-step-by-step-bringing-up-a-tunnel)
- [7. How a handshake is established and how traffic flows](#7-how-a-handshake-is-established-and-how-traffic-flows)
- [8. Interop testing against the kernel wolfGuard module](#8-interop-testing-against-the-kernel-wolfguard-module)
- [9. Troubleshooting](#9-troubleshooting)

---

## 1. What wolfGuard is

wolfGuard is a native wolfIP driver implementing the WireGuard tunnel protocol
on top of wolfSSL/wolfCrypt FIPS-certified primitives. It is WireGuard with the
cryptography replaced by FIPS-approved equivalents, so the construction string
is `Noise_IKpsk2_SECP256R1_AesGcm_SHA256` rather than the original
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (from `src/wolfguard/wolfguard.h`):

| WireGuard primitive | wolfGuard FIPS replacement |
|---|---|
| Curve25519 | ECDH with SECP256R1 (P-256) |
| ChaCha20-Poly1305 | AES-256-GCM |
| BLAKE2s | SHA-256 |
| BLAKE2s-HMAC | HMAC-SHA-256 |

wolfGuard peers interoperate with other wolfGuard instances, including the
[wolfGuard kernel module](https://github.com/wolfssl/wolfguard).

Supported:

- The full Noise IKpsk2 1-RTT handshake (initiation / response / cookie / data
  messages — `WG_MSG_INITIATION`, `WG_MSG_RESPONSE`, `WG_MSG_COOKIE`,
  `WG_MSG_DATA`).
- An optional pre-shared key (PSK) per peer for the IKpsk2 mixing step.
- Static, allocation-free state: a fixed peer table (`WOLFGUARD_MAX_PEERS`), a
  flat allowed-IPs table (`WOLFGUARD_MAX_ALLOWED_IPS`), and a per-peer replay
  window (`WOLFGUARD_COUNTER_WINDOW` bits).
- Cookie-based DoS mitigation (mac1/mac2 + cookie reply) when under load.
- The WireGuard timer state machine: rekey-on-time/messages, reject-after-time,
  persistent keepalive, and handshake retry with jitter.
- Per-peer staging of plaintext packets while a handshake is in flight
  (`WOLFGUARD_STAGED_PACKETS`).

**Not** supported / out of scope: interoperability with upstream Curve25519
WireGuard; IPv6 inner traffic (the TX path parses an IPv4 header only); dynamic
allocation; and IKE-style negotiation of the cipher suite (the suite is fixed by
the FIPS construction).

## 2. Building with wolfGuard

wolfGuard requires a wolfSSL built with wolfGuard support:

```sh
./configure --enable-wolfguard
make
sudo make install
```

In the wolfIP tree, wolfGuard is a separately-compiled module. The Makefile
defines its sources and flags (`Makefile`):

```make
WOLFGUARD_CFLAGS = -DWOLFGUARD -Wno-cpp
WOLFGUARD_SRC := src/wolfguard/wolfguard.c \
                 src/wolfguard/wg_noise.c \
                 src/wolfguard/wg_crypto.c \
                 src/wolfguard/wg_cookie.c \
                 src/wolfguard/wg_allowedips.c \
                 src/wolfguard/wg_packet.c \
                 src/wolfguard/wg_timers.c
```

The whole module is wrapped in `#ifdef WOLFGUARD`, so `-DWOLFGUARD` is the master
switch. The pre-wired Makefile targets build and exercise it:

```sh
make unit-wolfguard            # unit tests
make test-wolfguard-loopback   # two-stack loopback integration test
make test-wolfguard-interop    # interop binary (driven by the script in §8)
```

The unit and loopback tests also have AddressSanitizer / UBSan variants
(`unit-wolfguard-asan`, `unit-wolfguard-ubsan`,
`test-wolfguard-loopback-asan`, `test-wolfguard-loopback-ubsan`).

### Compile-time configuration

These tunables default in `src/wolfguard/wolfguard.h` and can be overridden in
`config.h` or via `-D`:

| Macro | Default | Meaning |
|-------|---------|---------|
| `WOLFGUARD_MAX_PEERS` | 8 | Max peers per device (`struct wg_device.peers[]`). |
| `WOLFGUARD_MAX_ALLOWED_IPS` | 32 | Max allowed-IP table entries. |
| `WOLFGUARD_STAGED_PACKETS` | 16 | Plaintext packets queued per peer during a handshake. |
| `WOLFGUARD_COUNTER_WINDOW` | 1024 | Anti-replay window size, in bits. |

Fixed protocol constants (also from `wolfguard.h`) follow the FIPS suite:
`WG_PUBLIC_KEY_LEN` is 65 (uncompressed P-256 point), `WG_PRIVATE_KEY_LEN` is 32,
`WG_SYMMETRIC_KEY_LEN` is 32 (AES-256), `WG_AUTHTAG_LEN` is 16 (AES-GCM tag), and
`WG_HASH_LEN` is 32 (SHA-256).

## 3. Mental model: the wg0 interface and the data path

wolfGuard plugs into wolfIP as an **L3 virtual interface** (conventionally
`wg0`). `wolfguard_init()` claims one of the stack's interface slots, marks it
`non_ethernet`, and installs send/poll callbacks (from
`src/wolfguard/wolfguard.c`). It also opens one wolfIP UDP socket bound to the
listen port — that socket is the *outer* transport that carries encrypted
WireGuard messages between endpoints.

Two interfaces are therefore in play:

- A **physical interface** (Ethernet or another `non_ethernet` link) carrying the
  outer UDP/IP traffic to the remote endpoint.
- The **wg0 interface** carrying *inner* plaintext IP traffic. Applications send
  to tunnel IPs (e.g. `10.0.0.2`) through ordinary `wolfIP_sock_*` calls; wolfIP
  routes those packets out of `wg0`, where wolfGuard encrypts them.

```text
  app sendto(10.0.0.2) ─▶ wolfIP routing ─▶ wg0.send ─▶ wolfguard_output()
                                                          │ allowed-IP lookup
                                                          ▼
                                                wg_packet_send() ── encrypt ──┐
                                                                              ▼
                              outer UDP socket  ◀─────────────────────  wolfIP_sock_sendto
                                    │                                   (to peer endpoint)
        ── wire (outer IP/UDP) ─────┘

  wire ─▶ outer UDP socket ─▶ wg_udp_callback() ─▶ wg_packet_receive()
                                                     │ decrypt + replay check
                                                     ▼
                                          wolfIP_recv_ex() into wg0 ─▶ app recv()
```

Two entry points drive the module from your loop, alongside `wolfIP_poll()`:

- **RX is push-based.** When an outer UDP datagram arrives, wolfIP invokes the
  registered `wg_udp_callback`, which drains the socket and calls
  `wg_packet_receive()`. Decrypted inner packets are injected straight into `wg0`
  via `wolfIP_recv_ex()`. The `wg0` poll callback returns `0` (no spontaneous
  data) by design — there is nothing to poll because all RX is push-based.
- **Timers are poll-based.** You call `wolfguard_poll(dev, now_ms)` once per loop
  iteration; it updates the device clock, evaluates the `under_load` flag, and
  ticks the timer state machine (`wg_timers_tick()`).

The application never sees WireGuard framing — it speaks plain UDP/TCP to tunnel
IPs and wolfGuard does the rest transparently inside the poll loop.

## 4. The public API

All public functions are declared in `src/wolfguard/wolfguard.h` and implemented
in `src/wolfguard/wolfguard.c`:

```c
int  wolfguard_init(struct wg_device *dev, struct wolfIP *stack,
                    unsigned int wg_if_idx, uint16_t listen_port);
int  wolfguard_set_private_key(struct wg_device *dev,
                               const uint8_t *private_key);
int  wolfguard_add_peer(struct wg_device *dev,
                        const uint8_t *public_key,
                        const uint8_t *preshared_key,
                        uint32_t endpoint_ip, uint16_t endpoint_port,
                        uint16_t persistent_keepalive);
int  wolfguard_add_allowed_ip(struct wg_device *dev, int peer_idx,
                              uint32_t ip, uint8_t cidr);
void wolfguard_poll(struct wg_device *dev, uint64_t now_ms);
int  wolfguard_output(struct wg_device *dev, const uint8_t *packet, size_t len);
void wolfguard_destroy(struct wg_device *dev);
```

- `wolfguard_init` zeroes `dev`, initialises its RNG, configures `wg_if_idx` as
  the `wg0` L3 interface (and sets its MTU to `WG_IF_MTU`, derived so that a
  full-size inner packet still fits in one outer UDP datagram after padding and
  encapsulation), opens the outer UDP socket, binds it to `listen_port`, and
  registers the RX callback. Returns `0` on success, `-1` on failure.
- `wolfguard_set_private_key` stores the 32-byte private key and derives the
  device's 65-byte public key (`wg_pubkey_from_private`). It must be called
  before adding peers; calling it again rotates the identity and drops live
  session keys and staged packets for all peers (preserving each peer's PSK).
- `wolfguard_add_peer` registers a peer by its 65-byte public key and returns the
  peer index (`>= 0`) or `-1` if the table is full. `preshared_key` may be `NULL`
  (no PSK). `endpoint_ip` / `endpoint_port` are in **network byte order**.
  `persistent_keepalive` is in seconds (`0` disables it).
- `wolfguard_add_allowed_ip` binds an IP/CIDR range to a peer in the allowed-IPs
  table. `ip` is in **network byte order**, `cidr` is the prefix length 0–32.
- `wolfguard_output` is the `wg0` send hook: it parses the inner IPv4 header,
  looks up the destination IP in the allowed-IPs table to find the peer, and
  hands the packet to `wg_packet_send()`. You normally do not call it directly —
  wolfIP routing invokes it through the interface `send` callback.
- `wolfguard_poll` drives the per-device timers; call it each loop after
  `wolfIP_poll()`.
- `wolfguard_destroy` zeroes all key material, closes the outer socket, and frees
  the RNG.

The lower-level helpers (Noise handshake in `wg_noise.c`, crypto in
`wg_crypto.c`, cookie/DoS in `wg_cookie.c`, allowed-IPs in `wg_allowedips.c`,
packet processing in `wg_packet.c`, timers in `wg_timers.c`) are also declared in
`wolfguard.h`, but the seven functions above are the supported integration
surface; the rest are driven internally.

## 5. Keys, peers and allowed IPs

A wolfGuard identity is a P-256 key pair. The **private key** is 32 raw bytes
(`WG_PRIVATE_KEY_LEN`); the **public key** is a 65-byte uncompressed SECP256R1
point (`WG_PUBLIC_KEY_LEN`). Generate a private key from the device RNG and let
wolfGuard derive the public key:

```c
uint8_t priv[WG_PRIVATE_KEY_LEN];
wc_RNG_GenerateBlock(&rng, priv, WG_PRIVATE_KEY_LEN);
wolfguard_set_private_key(&dev, priv);
/* dev.static_public now holds the 65-byte public key to share with peers */
```

Each peer is identified by its public key and an **endpoint** — the outer IP and
UDP port where its WireGuard messages are sent. The **allowed-IPs** table maps
inner tunnel IP ranges to peers and serves two purposes (mirroring upstream
WireGuard): on TX it selects which peer encrypts a packet, and on RX it is the
cryptokey-routing source-address check.

Endpoint and allowed-IP addresses are passed in **network byte order**. In the
wolfIP examples that means wrapping the host-order helper with `ee32()`/`ee16()`:

```c
/* from src/test/test_wolfguard_loopback.c */
peer_idx = wolfguard_add_peer(&wg_dev_a, wg_dev_b.static_public, NULL,
                              ee32(MAKE_IP4(192,168,1,2)),  /* endpoint IP   */
                              ee16(51820), 0);              /* endpoint port */
wolfguard_add_allowed_ip(&wg_dev_a, peer_idx,
                         ee32(MAKE_IP4(10,0,0,0)), 24);     /* 10.0.0.0/24   */
```

## 6. Step by step: bringing up a tunnel

The canonical end-to-end setup is `setup_loopback_stacks()` in
`src/test/test_wolfguard_loopback.c`, which connects two wolfIP stacks
back-to-back. Condensed to one side:

```c
/* 1. Bring up wolfIP and a physical (outer) interface as usual */
wolfIP_init(&stack_a);
ll = wolfIP_getdev_ex(&stack_a, TEST_PHYS_IF);
ll->non_ethernet = 1;
ll->poll = phys_a_poll;
ll->send = phys_a_send;
wolfIP_ipconfig_set_ex(&stack_a, TEST_PHYS_IF,
                       MAKE_IP4(192,168,1,1), MAKE_IP4(255,255,255,0), 0);

/* 2. Initialise wolfGuard on a second interface (wg0), listen UDP port 51820 */
wolfguard_init(&wg_dev_a, &stack_a, TEST_WG_IF, 51820);

/* 3. Provision our identity */
wc_RNG_GenerateBlock(&test_rng, priv_a, WG_PRIVATE_KEY_LEN);
wolfguard_set_private_key(&wg_dev_a, priv_a);

/* 4. Give the wg0 interface its tunnel IP */
wolfIP_ipconfig_set_ex(&stack_a, TEST_WG_IF,
                       MAKE_IP4(10,0,0,1), MAKE_IP4(255,255,255,0), 0);

/* 5. Add the remote peer (public key + endpoint) and its allowed inner range */
peer_idx = wolfguard_add_peer(&wg_dev_a, wg_dev_b.static_public, NULL,
                              ee32(MAKE_IP4(192,168,1,2)), ee16(51820), 0);
wolfguard_add_allowed_ip(&wg_dev_a, peer_idx,
                         ee32(MAKE_IP4(10,0,0,0)), 24);
```

The peer on the other end (`wg_dev_b`) installs the mirror image: it adds A's
public key, A's endpoint, and the same allowed-IP range. Public keys must be
exchanged out of band — each side passes the *other's* `static_public`.

Then run both pollers in your event loop, advancing a monotonic millisecond
clock (`pump_stacks()` in the test):

```c
wolfIP_poll(&stack_a, now);
wolfguard_poll(&wg_dev_a, now);
```

From here, application sockets bound to the `wg0` tunnel IPs send and receive
normally — the test sends a UDP datagram from `10.0.0.1` to `10.0.0.2:7777` with
an ordinary `wolfIP_sock_sendto()`, and it arrives decrypted on the far side.

## 7. How a handshake is established and how traffic flows

wolfGuard handshakes are **demand-driven**. There is no explicit "connect" call;
the first packet to a peer triggers the Noise exchange (from
`src/wolfguard/wg_packet.c`, `wg_packet_send()`):

1. An application sends to a tunnel IP. wolfIP routes the inner packet out
   `wg0`, calling `wolfguard_output()`, which resolves the peer via the
   allowed-IPs table and calls `wg_packet_send()`.
2. If the peer has no valid session keypair, the plaintext packet is **staged**
   (queued, up to `WOLFGUARD_STAGED_PACKETS`) and, if the handshake is idle, a
   `WG_MSG_INITIATION` is created (`wg_noise_create_initiation`) and sent to the
   peer's endpoint over the outer UDP socket.
3. The responder consumes the initiation, replies with `WG_MSG_RESPONSE`, and
   both sides derive the session keypair (`wg_noise_begin_session`) — the 1-RTT
   IKpsk2 handshake.
4. Once the session exists, staged packets are flushed
   (`wg_packet_send_staged`), encrypted as `WG_MSG_DATA` with AES-256-GCM, and
   sent. Subsequent packets encrypt directly.
5. Inbound `WG_MSG_DATA` is decrypted, replay-checked against the per-peer
   counter window (`wg_counter_validate`), and injected into `wg0`.

The timer state machine (`wg_timers_tick`, driven by `wolfguard_poll`) handles
the rest of the lifecycle: rekeying after `WG_REKEY_AFTER_TIME` (120 s) or
`WG_REKEY_AFTER_MESSAGES`, rejecting sessions older than `WG_REJECT_AFTER_TIME`
(180 s), retrying handshakes with jitter up to `WG_MAX_HANDSHAKE_ATTEMPTS`, and
sending keepalives when `persistent_keepalive` is configured. Under high
handshake load the device sets `under_load` and engages cookie-based DoS
mitigation (mac1/mac2 validation and `WG_MSG_COOKIE` replies in
`wg_cookie.c`).

## 8. Interop testing against the kernel wolfGuard module

The repository ships an end-to-end interop harness that validates bidirectional
tunnel connectivity between wolfIP and the Linux kernel wolfGuard module
(`tools/scripts/test-interop-wolfguard.sh`, driving the
`src/test/test_wolfguard_interop.c` binary). It requires root, kernel headers,
and network access (it clones and builds wolfSSL and the wolfGuard kernel
module):

```sh
sudo ./tools/scripts/test-interop-wolfguard.sh
```

What the script does:

1. Builds wolfSSL twice — the userspace library (`--enable-wolfguard`) and the
   kernel module (`--enable-wolfguard --enable-linuxkm`) — plus the `wg-fips`
   user tool and the `wolfguard.ko` kernel module from
   `github.com/wolfssl/wolfguard`.
2. Generates fresh P-256 keys with `wg-fips genkey` / `wg-fips pubkey`, then
   base64-decodes the wolfIP private key (32 bytes) and the kernel public key (65
   bytes) into raw `.bin` files for the wolfIP binary.
3. Builds `make test-wolfguard-interop` and launches it, which creates a TUN
   device for the outer transport.
4. Creates a kernel `wg0` interface (`ip link add wg0 type wolfguard`),
   configures it with `wg-fips set` (private key, listen port, the wolfIP peer
   public key, endpoint, and `allowed-ips`), assigns the tunnel IP, and starts a
   `socat` UDP echo server on the tunnel.

It then runs a two-phase test (matching the README):

1. **wolfIP initiates** — wolfIP creates the handshake, sends a UDP probe through
   the tunnel, and verifies the echo reply.
2. **Kernel initiates** — wolfIP resets its wolfGuard state; the kernel recreates
   `wg0` for a fresh handshake and sends data through the tunnel, which wolfIP
   verifies.

The default addressing the script uses: kernel `wg0` `10.0.0.1/24` listening on
51820, wolfIP `wg0` `10.0.0.2/24` listening on 51821, outer TUN
`192.168.77.1/2`, echo port 7777. Exit code `0` means all interop phases passed.

The `test-wolfguard-interop` binary takes the two key files as arguments and is
otherwise self-contained:

```sh
./build/test/test-wolfguard-interop <wolfip_priv.bin> <kernel_pub.bin>
```

The two-stack loopback test (`make test-wolfguard-loopback`) is the quicker
inner-loop check — it needs no kernel module and exercises the full TX/RX path,
rekey, key-zeroing on reconnect, and the cookie/DoS path between two in-process
wolfIP stacks.

## 9. Troubleshooting

- **The handshake never completes / no data arrives.** Confirm you call
  `wolfguard_poll(dev, now_ms)` every loop iteration with a *monotonic,
  advancing* millisecond clock — the handshake retry and rekey logic is entirely
  timer-driven. In the tests, time advances on every `pump_stacks()` step.
- **`wolfguard_output` returns `-1` / packets are silently dropped on TX.** The
  destination tunnel IP did not match any allowed-IP entry, or the matched peer
  is not active. Check that `wolfguard_add_allowed_ip` covers the inner
  destination and that `ip`/`cidr` are correct (IP in network byte order). The TX
  path also rejects anything that is not a well-formed IPv4 packet (first nibble
  must be `4`, length `>= 20`).
- **Endpoint or allowed-IP addresses look byte-swapped.** `endpoint_ip`,
  `endpoint_port`, and the allowed-IP `ip` are all **network byte order**.
  Convert host-order values with `ee32()` / `ee16()` as the examples do.
- **Nothing happens when a UDP message arrives on the listen port.** The RX
  callback drains *all* queued datagrams per invocation; if you reimplement the
  socket plumbing, replicate that loop — reading a single packet leaves stale
  messages in the FIFO that corrupt later handshakes (see `wg_udp_callback` in
  `wolfguard.c`).
- **It will not talk to stock WireGuard.** Expected — wolfGuard uses the FIPS
  suite (P-256 / AES-GCM / SHA-256) and is interoperable only with other
  wolfGuard peers (kernel module or another wolfIP instance).
- **Inner MTU surprises.** `wolfguard_init` sets the `wg0` MTU to `WG_IF_MTU`
  (1454 with the usual `LINK_MTU` of 1536), leaving a 1440-byte inner IP budget
  and 1412 bytes of UDP payload; size inner payloads accordingly. The
  reservation is not a flat header sum: the plaintext is padded up to a 16-byte
  multiple before encryption, the outer IP payload is capped at 1500 rather
  than `LINK_MTU`, and wolfIP subtracts a 14-byte link header from every
  interface MTU including this one. Raising the `wg0` MTU past `WG_IF_MTU`
  black-holes the largest packets rather than failing loudly, since the outer
  `sendto()` rejects them after wolfIP has already accepted them.

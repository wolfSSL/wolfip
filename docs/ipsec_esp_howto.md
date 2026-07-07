# IPsec ESP How-To

This guide shows how to secure wolfIP traffic with **IPsec ESP in transport
mode**: how to build wolfIP with ESP support, how to install Security
Associations (SAs), and how to interoperate with the Linux kernel's IPsec
stack for testing.

It is a getting-started document, not a reference manual. The authoritative API
is `wolfesp.h`; the worked examples come from `src/test/esp/` and the
`ip xfrm` helper scripts in `tools/ip-xfrm/`.

## Table of Contents

- [1. What wolfIP ESP does (and does not) do](#1-what-wolfip-esp-does-and-does-not-do)
- [2. Building with ESP support](#2-building-with-esp-support)
- [3. Mental model: SAs and the data path](#3-mental-model-sas-and-the-data-path)
- [4. The SA API](#4-the-sa-api)
- [5. Step by step: securing a socket](#5-step-by-step-securing-a-socket)
- [6. Choosing a cipher suite](#6-choosing-a-cipher-suite)
- [7. Key material and IV/nonce handling](#7-key-material-and-ivnonce-handling)
- [8. Interoperating with Linux `ip xfrm`](#8-interoperating-with-linux-ip-xfrm)
- [9. Inspecting ESP traffic in Wireshark](#9-inspecting-esp-traffic-in-wireshark)
- [10. Troubleshooting](#10-troubleshooting)

---

## 1. What wolfIP ESP does (and does not) do

wolfIP implements the ESP datagram format (RFC 4303) in **transport mode**: it
encrypts and authenticates the payload of an IPv4 packet (the TCP/UDP/ICMP
segment) while leaving the IP header in the clear. When an SA matches, an
outbound packet is wrapped into ESP before it leaves the interface, and an
inbound ESP packet (IP protocol number 50) is unwrapped and verified before the
stack dispatches it to TCP/UDP/ICMP.

Supported:

- **Transport mode** only.
- Cipher suites: AES-CBC + HMAC (RFC 3602 / 4868), 3DES-CBC + HMAC (RFC 2451),
  AES-GCM (RFC 4106), AES-GMAC (RFC 4543).
- A small static pool of SAs (`WOLFIP_ESP_NUM_SA`, default 2 inbound + 2
  outbound) with a 32-packet anti-replay window.

The ESP data path is deliberately scoped for embedded use. Tunnel mode, UDP
encapsulation of ESP, IPv6, ESP across forwarded/routed packets, and a full SPD
(security policy database) with port/proto selectors are outside the current
scope — matching is by `{src IP, dst IP, SPI}`. These can be added as
deployments come to need them.

**No IKE is a design choice, not a gap.** You provision keys out of band on both
peers, exactly as you would with a manually-keyed `ip xfrm state` on Linux. For
embedded line rates, devices are not expected to rekey often or to exhaust an SA
rapidly, so an online key-exchange daemon buys little for the code and attack
surface it adds. Sequence numbers are 32-bit, which comfortably covers the
packet volumes these links carry between planned key rotations.

## 2. Building with ESP support

ESP relies on wolfCrypt for the cipher and HMAC primitives, so you need wolfSSL
installed first. To exercise all suites, build it with 3DES and the streaming
AES-GCM API:

```sh
./configure --enable-des3 --enable-aesgcm-stream
make
sudo make install
```

This is a full wolfSSL build so a single library can exercise every ESP suite
for interop testing. A practical deployment does not need all of it: ESP only
uses wolfCrypt, so you can build with `--enable-cryptonly` and enable just the
specific algorithms your SAs use (for example only AES-GCM), which yields a much
slimmer library.

Then compile wolfIP with the ESP feature flags (`Makefile`, `ESP_CFLAGS`):

```
-DWOLFIP_ESP -DWOLFSSL_WOLFIP
```

A plain `make` in the wolfIP tree already produces the two ESP example
binaries, linked against `-lwolfssl`:

- `./build/test-esp` — a self-contained event-loop test that spawns both an ESP
  client and server.
- `./build/esp-server` — an ESP echo server (TCP or UDP) you can drive from the
  Linux host.

When ESP is enabled, `src/wolfesp.c` is included directly into `src/wolfip.c`
(see the `#include "src/wolfesp.c"` guarded by `WOLFIP_ESP`), so the ESP hooks
are compiled into the core data path rather than linked as a separate module.

## 3. Mental model: SAs and the data path

An **SA (Security Association)** is a one-way agreement on how to protect a flow:
a direction, a `{src, dst}` IP pair, an SPI (a 4-byte tag carried in every ESP
packet so the receiver knows which SA to use), and the cipher/auth keys. A
two-way TCP connection therefore needs **two** SAs: one outbound and one
inbound.

wolfIP keeps two separate pools:

- **inbound SAs** — consulted when a packet with IP protocol 50 arrives. wolfIP
  reads the SPI from the ESP header, finds the matching inbound SA, verifies the
  ICV, decrypts, and hands the plaintext packet to the normal input path.
- **outbound SAs** — consulted just before a packet is transmitted. If an
  outbound SA matches the packet's `{src, dst}`, wolfIP encrypts and wraps it as
  ESP; otherwise the packet goes out in the clear.

```text
  socket send ─▶ TCP/UDP build ─▶ [outbound SA match?] ─yes▶ ESP wrap ─▶ wire
                                          │no
                                          └────────────────────────────▶ wire

  wire ─▶ IP input ─▶ [proto == 50 (ESP)?] ─yes▶ inbound SA lookup by SPI
                            │no                   ─▶ verify ICV ─▶ decrypt
                            └─▶ TCP/UDP/ICMP ◀──────────────────────┘
```

The application never sees ESP. You install SAs once at startup, then use
ordinary `wolfIP_sock_*` calls (or the BSD wrapper). Encryption happens
transparently inside `wolfIP_poll()`.

## 4. The SA API

All functions are declared in `wolfesp.h`. Initialise the subsystem once, then
install one SA per direction. The first argument `in` selects the pool:
`1` = inbound, `0` = outbound.

```c
int  wolfIP_esp_init(void);
void wolfIP_esp_sa_del_all(void);
void wolfIP_esp_sa_del(int in, uint8_t *spi);

/* AEAD: AES-GCM (RFC 4106) or AES-GMAC (RFC 4543) */
int  wolfIP_esp_sa_new_gcm(int in, uint8_t *spi, ip4 src, ip4 dst,
                           esp_enc_t enc, uint8_t *enc_key, uint8_t enc_key_len);

/* Authentication-only (NULL encryption) HMAC SA */
int  wolfIP_esp_sa_new_hmac(int in, uint8_t *spi, ip4 src, ip4 dst,
                            esp_auth_t auth, uint8_t *auth_key,
                            uint8_t auth_key_len, uint8_t icv_len);

/* AES-CBC encryption + HMAC authentication */
int  wolfIP_esp_sa_new_cbc_hmac(int in, uint8_t *spi, ip4 src, ip4 dst,
                                uint8_t *enc_key, uint8_t enc_key_len,
                                esp_auth_t auth, uint8_t *auth_key,
                                uint8_t auth_key_len, uint8_t icv_len);

/* 3DES-CBC encryption + HMAC authentication (key length fixed at 24 bytes) */
int  wolfIP_esp_sa_new_des3_hmac(int in, uint8_t *spi, ip4 src, ip4 dst,
                                 uint8_t *enc_key, esp_auth_t auth,
                                 uint8_t *auth_key, uint8_t auth_key_len,
                                 uint8_t icv_len);
```

`spi` is a 4-byte array. `src`/`dst` are `ip4` values in **network byte order**
(use `atoip4("a.b.c.d")`). All functions return `0` on success and a negative
error on failure (for example, when the SA pool is full — raise
`WOLFIP_ESP_NUM_SA` if you need more than two SAs per direction).

The relevant cipher/auth enums (`wolfesp.h`):

```c
typedef enum { ESP_ENC_NONE, ESP_ENC_CBC_AES, ESP_ENC_CBC_DES3,
               ESP_ENC_GCM_RFC4106, ESP_ENC_GCM_RFC4543 } esp_enc_t;

typedef enum { ESP_AUTH_NONE, ESP_AUTH_MD5_RFC2403, ESP_AUTH_SHA1_RFC2404,
               ESP_AUTH_SHA256_RFC4868, ESP_AUTH_GCM_RFC4106,
               ESP_AUTH_GCM_RFC4543 } esp_auth_t;
```

ICV length constants: `ESP_ICVLEN_HMAC_96` (12) and `ESP_ICVLEN_HMAC_128` (16)
for HMAC suites; `ESP_GCM_RFC4106_ICV_LEN` (16) for GCM.

## 5. Step by step: securing a socket

The `esp-server` example (`src/test/esp/esp_server.c`) is the canonical
walk-through. The structure is: init the ESP subsystem, install the inbound and
outbound SAs, then open and use sockets normally.

```c
#include "wolfip.h"
#include "wolfesp.h"

/* SPIs (any unique 4-byte tags, agreed with the peer) */
static uint8_t in_spi[ESP_SPI_LEN]  = { 0x03, 0x03, 0x03, 0x03 };
static uint8_t out_spi[ESP_SPI_LEN] = { 0x04, 0x04, 0x04, 0x04 };

/* AES-CBC keys (32 bytes) + HMAC-SHA256 keys (16 bytes), shared with the peer */
static uint8_t in_enc[32]  = { /* ... */ };
static uint8_t out_enc[32] = { /* ... */ };
static uint8_t in_auth[16]  = { /* ... */ };
static uint8_t out_auth[16] = { /* ... */ };

#define WOLFIP_IP    "10.10.10.2"   /* this node */
#define PEER_IP      "10.10.10.1"   /* the other end */

int secure_init(void)
{
    int err = wolfIP_esp_init();
    if (err) return err;

    /* Inbound SA: packets FROM the peer TO us. src = peer, dst = us. */
    err = wolfIP_esp_sa_new_cbc_hmac(1, in_spi,
            atoip4(PEER_IP), atoip4(WOLFIP_IP),
            in_enc, sizeof(in_enc),
            ESP_AUTH_SHA256_RFC4868, in_auth, sizeof(in_auth),
            ESP_ICVLEN_HMAC_128);
    if (err) return err;

    /* Outbound SA: packets FROM us TO the peer. src = us, dst = peer. */
    err = wolfIP_esp_sa_new_cbc_hmac(0, out_spi,
            atoip4(WOLFIP_IP), atoip4(PEER_IP),
            out_enc, sizeof(out_enc),
            ESP_AUTH_SHA256_RFC4868, out_auth, sizeof(out_auth),
            ESP_ICVLEN_HMAC_128);
    return err;
}
```

After `secure_init()` succeeds, application code is unchanged — open a socket,
`bind`, `listen`/`accept` or `connect`, then `send`/`recv`. Every packet that
matches the outbound SA is encrypted on the way out, and matching inbound ESP
packets are verified and decrypted before your `recv` sees them.

Note the **src/dst asymmetry** between the two SAs: the inbound SA's `dst` is
this node, the outbound SA's `src` is this node. The peer installs the mirror
image (its inbound SA = our outbound SA, same SPI and keys). Getting this
backwards is the most common cause of "packets go out encrypted but nothing
comes back."

## 6. Choosing a cipher suite

The `esp-server` example exposes all four supported suites via `-m <mode>`,
which is a convenient map of what to call:

| Mode | Suite | Constructor | Notes |
|------|-------|-------------|-------|
| 0 | AES-GCM (RFC 4106) | `wolfIP_esp_sa_new_gcm(..., ESP_ENC_GCM_RFC4106, ...)` | AEAD; needs `--enable-aesgcm-stream`. Recommended. |
| 1 | AES-CBC + HMAC-SHA256 | `wolfIP_esp_sa_new_cbc_hmac(...)` | Encrypt-then-MAC; widely interoperable. |
| 2 | 3DES-CBC + HMAC-SHA256 | `wolfIP_esp_sa_new_des3_hmac(...)` | Legacy; needs `--enable-des3`. |
| 3 | AES-GMAC (RFC 4543) | `wolfIP_esp_sa_new_gcm(..., ESP_ENC_GCM_RFC4543, ...)` | Authentication only, no confidentiality. |

For new designs prefer **AES-GCM (mode 0)**: a single AEAD pass for both
confidentiality and integrity, and the smallest per-packet overhead of the
encrypting suites.

## 7. Key material and IV/nonce handling

A few practical rules drawn from the example key tables
(`src/test/esp/esp_common.c`):

- **GCM/GMAC keys carry a 4-byte salt.** For the RFC 4106/4543 constructors the
  key buffer is the cipher key **plus** a trailing 4-byte nonce salt. The
  example uses a 36-byte buffer (32-byte AES-256 key + 4-byte salt) and passes
  `sizeof(key)` (36). The salt may be public and is shared with the peer; you
  never supply a per-packet IV yourself.
- **The GCM nonce is built deterministically** following NIST SP 800-38D
  §8.2.1. At SA creation wolfIP draws an 8-byte random pre-IV from
  `wc_RNG_GenerateBlock()`; per packet, the low 32 bits of that pre-IV are XORed
  with the ESP sequence number to form the 8-byte IV, and the 4-byte salt is
  prepended to make the 12-byte GCM nonce. This gives a monotonic counter with a
  random starting point, so nonces never repeat under a given key.
- **CBC/3DES keys do not carry the salt.** When reusing the same key bytes for
  a CBC SA, pass `sizeof(key) - 4` to drop the trailing salt (the example does
  exactly this: `sizeof(in_enc_key) - 4`). The CBC IV is generated randomly per
  packet from wolfCrypt's RNG.
- **3DES keys are fixed at 24 bytes** (`ESP_DES3_KEY_LEN`); the constructor does
  not take a length argument.
- **HMAC auth keys** are typically 16 bytes for HMAC-SHA256; the ICV length you
  pass (`ESP_ICVLEN_HMAC_96` or `_128`) must match the peer.

Keys must be identical on both peers for a given SPI/direction, and the
inbound/outbound pairing must mirror the peer's. Use real, independently
generated random keys in production — the all-`0x03`/`0x04` values in the
examples are for interop testing only.

## 8. Interoperating with Linux `ip xfrm`

The `tools/ip-xfrm/` scripts configure the Linux kernel as the ESP peer so you
can test wolfIP against a reference implementation. Each script installs the
matching `ip xfrm state` (the SAs) and `ip xfrm policy` (when to apply them) for
one suite:

| Script | Suite |
|--------|-------|
| `cbc_auth`  | AES-CBC (RFC 3602) + HMAC (RFC 2403/2404/4868) |
| `des3_auth` | 3DES-CBC (RFC 2451) + HMAC |
| `rfc4106`   | AES-GCM (RFC 4106) |
| `rfc4543`   | AES-GMAC (RFC 4543) |
| `show`      | dump all xfrm state and policies |
| `delete_all`| remove all xfrm state and policies |

The keys baked into these scripts match `src/test/esp/esp_common.c` and the SPIs
in `esp_sa.txt`, so a wolfIP example and the corresponding script form a working
pair out of the box. An AES-GCM state entry, for instance, looks like
(`tools/ip-xfrm/rfc4106`):

```sh
sudo ip xfrm state add \
  src 10.10.10.1 dst 10.10.10.2 \
  proto esp spi 0x01010101 mode transport replay-window 64 \
  aead 'rfc4106(gcm(aes))' 0x0303...0a0b0c0d 128 \
  sel src 10.10.10.1 dst 10.10.10.2
```

Note the AEAD key ends in `0a0b0c0d` — the same 4-byte salt wolfIP appends to
its GCM key, confirming the salt convention.

**End-to-end test (AES-GCM, self-contained loop):**

```sh
./tools/ip-xfrm/rfc4106 128
sudo LD_LIBRARY_PATH=/usr/local/lib ./build/test-esp
./tools/ip-xfrm/delete_all
```

**End-to-end test (3DES + HMAC, UDP echo server driven from the host):**

```sh
# terminal 1 — configure the Linux peer
./tools/ip-xfrm/delete_all
./tools/ip-xfrm/des3_auth sha256 128 udp

# terminal 2 — run the wolfIP ESP echo server
sudo LD_LIBRARY_PATH=/usr/local/lib ./build/esp-server -m 2 -u

# terminal 1 again — talk to it; bytes arrive/return as ESP packets
nc 10.10.10.2 8 -p 12345 -u
```

Always run `./tools/ip-xfrm/delete_all` between tests so stale SAs do not
shadow the new ones.

## 9. Inspecting ESP traffic in Wireshark

Because you hold the keys, you can decrypt and verify the captured ESP packets.
Copy the provided Wireshark `esp_sa` config and open a capture:

```sh
cp tools/ip-xfrm/esp_sa.txt ~/.config/wireshark/esp_sa
wireshark test.pcap
```

Wireshark will then show the decrypted inner TCP/UDP payload, validate the ESP
ICV, and check the inner IP/transport checksums — invaluable when debugging a
suite mismatch or a bad key.

## 10. Troubleshooting

**Outbound packets are encrypted but no reply arrives.** The inbound SA's
`{src, dst}` is almost certainly reversed. Inbound `src` = peer, `dst` = this
node; outbound is the opposite. Confirm the peer's SAs are the mirror image.

**Inbound ESP packets are silently dropped.** Causes: SPI mismatch (the receiver
looks up the SA by SPI), wrong key, wrong ICV length, or a suite mismatch.
wolfIP logs `failed to unwrap esp packet, dropping` on the input path; capture
with Wireshark + `esp_sa` to see which check fails.

**`error: gcm stream not built in` / `des3 not built in`.** wolfSSL was built
without `--enable-aesgcm-stream` or `--enable-des3`. Rebuild wolfSSL with the
needed options and reinstall.

**SA creation returns a negative error.** The static pool is full. Increase
`WOLFIP_ESP_NUM_SA` (default 2 per direction) at compile time.

**ESP packets on an interface marked `non_ethernet` are dropped.** ESP transport
unwrap currently runs only on Ethernet interfaces; L3-only links are not
supported on the inbound ESP path.

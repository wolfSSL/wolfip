# Integrating a DLR implementation with wolfIP

## Table of Contents

1. [Scope](#1-scope)
2. [What DLR needs that wolfIP does not have](#2-what-dlr-needs-that-wolfip-does-not-have)
3. [The L2 protocol hook](#3-the-l2-protocol-hook)
4. [The switch control vtable](#4-the-switch-control-vtable)
5. [Timing constraints](#5-timing-constraints)
6. [Driver checklist](#6-driver-checklist)
7. [Status and open items](#7-status-and-open-items)

---

## 1. Scope

**wolfIP does not implement DLR.** This document describes the integration
surface wolfIP exposes so that a Device Level Ring implementation — written
in-house or supplied by a third party — can be layered on top without
modifying the core stack.

DLR is ODVA's Ethernet ring-redundancy protocol, specified in the *CIP
Networks Library, Volume 2: EtherNet/IP Adaptation of CIP*, chapter 9, and
referenced by IEC 61784-2. It provides sub-10ms recovery on a single ring of
two-port devices: a designated ring supervisor blocks one of its ports to
break the loop, watches for beacon loss, and unblocks on a fault.

> **The ODVA specification is not publicly available.** Values quoted in this
> document — notably the DLR ethertype `0x80E1` and the
> `01:21:6C:00:00:0x` multicast MAC range — must be confirmed against the
> specification before being committed to code. They are recorded here to
> describe the *shape* of the integration, not as normative constants.

Two things from an earlier draft are explicitly **not** part of this work:

- **ISO 11898 / CAN FD.** ISO 11898 is the CAN bus standard; ISO 11898-5 is
  "high-speed medium access unit with low-power mode". It has nothing to do
  with DLR and nothing to do with an Ethernet IP stack.
- **DLR over anything but Ethernet.** DLR is an Ethernet ring protocol.

---

## 2. What DLR needs that wolfIP does not have

| Need | wolfIP before this change | Provided by |
|---|---|---|
| Receive frames of a non-IP ethertype | Only `0x0800`, `0x0806`, `0x8100`, and `0x888E` hardwired in the demux | `wolfIP_register_l2_handler()` |
| Receive frames sent to a protocol-specific multicast MAC | Ingress filter accepts unicast, broadcast, and IP multicast mappings only | `accept_macs` argument of the same call |
| Know which of the two ports a frame arrived on | No port concept; `wolfIP_ll_dev` is one interface | `switch_ops->last_rx_port()` |
| Send a frame out of one specific port | `wolfIP_ll_send_frame()` targets an interface | `switch_ops->send_on_port()` |
| Block ordinary traffic on a port while still passing ring frames | No port control | `switch_ops->port_set_blocked()` |
| Detect a link transition quickly | No link state reporting | `switch_ops->set_link_change_cb()` |
| Flush the switch MAC table after a topology change | Not applicable | `switch_ops->flush_mac_table()` |
| Beacon every few hundred microseconds | Poll loop is millisecond-granular | **Not provided** — see §5 |

---

## 3. The L2 protocol hook

```c
int wolfIP_register_l2_handler(struct wolfIP *s, uint16_t ethertype,
                               int (*handler)(void *ctx, unsigned int if_idx,
                                              const uint8_t *frame,
                                              uint32_t len),
                               void *ctx,
                               const uint8_t *accept_macs, unsigned int count);
```

This generalises the existing `wolfIP_register_eapol_handler()`, which does
the same job for ethertype `0x888E` only. A DLR module registers `0x80E1`
along with the ring multicast MAC addresses it must receive.

Two details matter and are easy to get wrong:

- **`frame`/`len` cover the entire Ethernet frame, header included.** The
  EAPOL hook strips the 14-byte header before calling out; a ring protocol
  cannot afford that, because it needs the source MAC to identify the
  advertising node.
- **`accept_macs` is not optional for DLR.** The ingress path filters on
  destination MAC before it reaches any dispatch. A protocol using its own
  multicast group that does not declare its MACs will simply never be
  called, and the failure is silent.

---

## 4. The switch control vtable

```c
struct wolfIP_switch_ops {
    int (*port_count)(struct wolfIP_ll_dev *ll);
    int (*port_link_state)(struct wolfIP_ll_dev *ll, unsigned int port);
    int (*set_link_change_cb)(struct wolfIP_ll_dev *ll,
                              void (*cb)(void *ctx, unsigned int port, int up),
                              void *ctx);
    int (*port_set_blocked)(struct wolfIP_ll_dev *ll, unsigned int port,
                            int blocked);
    int (*flush_mac_table)(struct wolfIP_ll_dev *ll, int port_or_all);
    int (*send_on_port)(struct wolfIP_ll_dev *ll, unsigned int port,
                        void *buf, uint32_t len);
    int (*last_rx_port)(struct wolfIP_ll_dev *ll);
};
```

A driver publishes this by setting `ll->switch_ops`. It is `NULL` on every
ordinary single-port driver, and the field is appended **last** in
`struct wolfIP_ll_dev`, after `wifi_ops`, so that adding it does not shift
the offset of any pre-existing member. That is the same ABI convention the
Wi-Fi vtable follows, and it is why ports do not need recompiling.

**`port_set_blocked()` carries the subtlety.** A blocked port must continue
to pass frames whose ethertype has been claimed through
`wolfIP_register_l2_handler()`. If the hardware filter is all-or-nothing,
the ring protocol stops seeing its own beacons across the block and the ring
never converges. Drivers that cannot express this selectively should say so
rather than approximating it.

---

## 5. Timing constraints

This is the part that cannot be papered over.

wolfIP's poll loop is millisecond-granular: `wolfIP_poll(s, now)` takes a
millisecond timestamp, and the timer heap is built on it. DLR beacon
intervals are **sub-millisecond** (hundreds of microseconds), with beacon
timeouts a small multiple of that.

Therefore:

- A DLR implementation **must** drive beacon transmission and the beacon
  timeout from its own hardware timer or a dedicated high-priority task.
  wolfIP's timers are not suitable and `struct wolfIP_switch_ops` does not
  pretend to offer them.
- `set_link_change_cb()` exists because link-down detection via polling
  would be far too slow. Recovery within the DLR budget depends on the PHY
  interrupt path, not on the stack's poll cadence.
- Beacon transmission should go through `send_on_port()` directly rather
  than through wolfIP's transmit path, which is designed around a
  poll-driven flush and offers no latency guarantee.

In short: wolfIP is the IP stack alongside the ring protocol, not the engine
driving it.

---

## 6. Driver checklist

For a two-port part intended to support DLR:

- [ ] `ll->switch_ops` populated, `port_count()` returning 2.
- [ ] `send_on_port()` reaches each external port individually, bypassing
      the switch's normal forwarding decision.
- [ ] `last_rx_port()` reports the ingress port of the frame most recently
      handed to `wolfIP_recv_ex()`.
- [ ] `port_set_blocked()` blocks ordinary traffic while still passing
      claimed ethertypes.
- [ ] `flush_mac_table()` clears learned entries, per port and for all.
- [ ] `set_link_change_cb()` fires from the PHY link-change interrupt, not
      from a poll.
- [ ] A hardware timer is available to the DLR module at sub-millisecond
      resolution.

---

## 7. Status and open items

**Declared, not implemented.** `struct wolfIP_switch_ops` and
`wolfIP_register_l2_handler()` are part of the public header so that driver
and integration work can proceed against a stable contract. The stack side
of `wolfIP_register_l2_handler()` — the registration table and the demux and
MAC-filter changes that consume it — is not written yet, and no driver
currently populates `switch_ops`.

Open items before an implementation lands:

1. Confirm the DLR ethertype and multicast MAC range against the ODVA
   specification.
2. Decide the size of the registered-protocol table and whether it is
   per-interface or global.
3. Decide whether `accept_macs` should support a prefix match. Exact
   matching covers DLR; other protocols may want `33:33:*`-style rules.
4. Settle whether a blocked port is a property the stack should know about,
   or remain entirely inside the driver and the DLR module.

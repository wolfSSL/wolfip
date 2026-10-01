# wolfIP protocol scope decisions

Features the protocol specifications require but wolfIP deliberately does not
implement. Each entry records the decision, the rationale, and the date, so a
standards review (or a scanner) sees a documented scope-out, not an oversight.

## TCP urgent data (RFC 9293 §3.8.5) - not supported by design

**Decision:** 2026-10-01 (Daniele Lacamera). wolfIP's TCP receiver does not
process the URG flag or the urgent pointer of incoming segments, and the
socket layer provides no out-of-band notification. The `urg` field is carried
in `struct wolfIP_tcp_seg` for wire completeness and is sent as 0.

**Rationale:** RFC 9293 §3.8.5 tells new applications not to employ the
mechanism (SHLD-13), and the supporting MUSTs (MUST-30 urgent pointer,
MUST-31 arbitrary-length sequences, MUST-32 asynchronous notification,
MUST-33 remaining-urgent-data query, MUST-62 pointer semantics, MUST-66
processing at a zero window) would require OOB notification API and
pointer-tracking state the stack does not carry. wolfIP's socket model is
callback-based with an in-band data stream; urgent data would be delivered
inline, unmarked, which is what a peer gets from a receiver that ignores the
pointer. Segments carrying URG are otherwise processed normally: the data is
in-band per RFC 9293 §3.8.5 ("the urgent pointer ... points into the
transmission stream"), so ignoring the pointer loses no data.

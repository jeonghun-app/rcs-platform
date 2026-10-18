# ADR 0004 — MSRP is anchored by a relay that pcscf controls

**Status:** accepted

## Context

`rcs-as` runs in private subnets and must terminate MSRP (store-and-forward, IMDN,
group fan-out). Clients are on the internet, usually behind NAT. RCS clients do not
generally implement RFC 4976 relays; operator networks anchor MSRP in an IMS access
gateway controlled by the P-CSCF (TS 23.334).

## Decision

- `msrp-relay` is an MSRP back-to-back relay at the edge. `pcscf` asks it for a
  binding through `POST /v1/bindings` and rewrites `m=message` SDP in both
  directions.
- Connection direction: **the client connects to the relay, and the relay connects
  to `rcs-as`**. RFC 6135 §4.2.2 forbids `a=setup:passive` in an offer, so the
  direction is reached through answers, never by offering `passive`:

  | Session | Offer the far side sees | Answer the offerer sees |
  |---|---|---|
  | Client originates (client offers `actpass` or `active`) | to `rcs-as`: relay core address, `active`; `rcs-as` answers `passive` | to client: relay public address, `passive` |
  | `rcs-as` originates (`rcs-as` offers `actpass`, its instance address) | to client: relay public address, `actpass` | to `rcs-as`: `active` (relay connects) |

  - On the core leg the relay offers `active` (port 9), which forces a `passive`
    answer: it does not listen on its core address, and RFC 6135 §4.2.2 requires
    `active` from an endpoint that cannot provide a transport address it accepts
    connections on. The relay still sends an explicit `a=setup` (§4.2.1).
  - A missing `a=setup` takes the RFC 4145 §4 defaults (`active` in an offer,
    `passive` in an answer), so a client without connection negotiation
    (RFC 6135 §5) is served.
  - A client answering the terminating `actpass` offer with `passive` asks the
    network to dial it. The relay **never dials clients** (a client-supplied
    target is an SSRF and port-scanning vector, and the outbound leg could not
    use the NLB's TLS). The answer arrives in a 2xx, which a proxy must forward
    (RFC 3261 §16.7). `pcscf` first releases the relay binding, so the relay never
    connects to `rcs-as` for this session, then forwards the 2xx and, once the
    ACK from `rcs-as` has passed through, ends the session as a P-CSCF may
    (TS 24.229 §5.2.10, clause to confirm against the targeted edition): BYE
    toward the client and toward `rcs-as`, both with
    `Reason: SIP;cause=488;text="MSRP direction not supported"`.
    `rcs-as` treats a BYE carrying that Reason before any MSRP traffic as a
    delivery failure on this contact (see Consequences for what it does next).
    Clients behind NAT answer `active` (§4.2.2), so this affects only clients
    that are themselves reachable.
- `rcs-as` offers `actpass` with its instance address and answers `passive`;
  every MSRP endpoint in the platform always sends an explicit `a=setup`
  (§4.2.1) and never sends `holdconn`.
- Bindings are stored in DynamoDB with a TTL and keyed by the session id in the
  relay URI, so any relay task can accept any client connection.
  - The session id carries at least 128 random bits (base32), so it cannot be
    guessed; it is the only thing that ties a client connection to a binding.
  - Lookups use **strongly consistent reads**: a client may connect milliseconds
    after another task wrote the binding.
  - The binding stores its own expiry and the relay checks it on read; DynamoDB
    TTL deletion can lag by days and only keeps the table small.
  - A binding accepts one client connection; a second connection presenting the
    same session id is refused with a 403 and logged. The relay task that
    accepts the connection claims the binding with a conditional update
    (`attribute_not_exists(claimed_by)`), so the rule holds across tasks.
- RFC 4976 relay mode (AUTH) is an optional later feature for clients that ask for
  it.

## Rationale

Making the client always the connecting side removes the need for connection
affinity behind the NLB, works through NAT, and means the relay never opens a
connection to an address a client chose. Using the gateway model matches how operators deploy
RCS and keeps the client unaware of the relay.

## Consequences

- `pcscf` must rewrite SDP correctly in offers and answers, initial and re-INVITE,
  and release bindings on BYE, CANCEL, failure responses and session timer expiry.
- A client that offers `a=setup:passive` violates RFC 6135 §4.2.2; `pcscf`
  answers such an offer with 488 Not Acceptable Here.
- A client that answers a terminating offer with `passive` cannot receive chat
  sessions from the network. `rcs-as` delivers to it with **pager-mode
  standalone messaging** (SIP MESSAGE, no MSRP) when the message fits the pager
  limit; larger content stays stored and is delivered inside the next session the
  client itself originates to that conversation, until the store-and-forward
  expiry (`RCSAS_STORE_TTL`, default 7 days), after which the sender gets a
  negative delivery notification. `rcs-as` does not retry terminating sessions to
  that contact while it stays registered on the same flow; a registration on a
  new flow clears the marker. Recorded as a limitation; the count is a metric.
- The relay needs no internet egress.

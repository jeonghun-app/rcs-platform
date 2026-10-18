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
    answer, because it does not accept connections from the core. The relay is a
    media gateway, not a UA; the §4.2.2 `actpass` rule addresses endpoints that
    can be reached, which the relay's core side deliberately cannot.
  - A missing `a=setup` takes the RFC 4145 §4 defaults (`active` in an offer,
    `passive` in an answer), so a client without connection negotiation
    (RFC 6135 §5) is served.
  - A client answering the terminating `actpass` offer with `passive` asks the
    network to dial it. The relay **never dials clients** (a client-supplied
    target is an SSRF and port-scanning vector, and the outbound leg could not
    use the NLB's TLS). `pcscf` releases the binding and returns 488 toward
    `rcs-as`, which keeps the message for store-and-forward and retries on the
    next registration. Clients behind NAT answer `active` (§4.2.2), so this
    affects only clients that are themselves reachable.
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
  sessions; its messages are stored and delivered when it next originates or
  through standalone messaging. Recorded as a limitation; the count is a metric.
- The relay needs no internet egress.

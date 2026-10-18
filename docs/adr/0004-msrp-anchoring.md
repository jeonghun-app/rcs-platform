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
- Toward the client the relay is always **passive** (`a=setup:passive`, its public
  address in `a=path`); toward `rcs-as` it is always **active**. Clients always
  connect to the relay; the relay always connects to `rcs-as`.
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

Fixing the connection direction removes the need for connection affinity behind
the NLB and works through NAT. Using the gateway model matches how operators deploy
RCS and keeps the client unaware of the relay.

## Consequences

- `pcscf` must rewrite SDP correctly in offers and answers, initial and re-INVITE,
  and release bindings on BYE, CANCEL, failure responses and session timer expiry.
- A client that offers `a=setup:passive` when it originates a session asks the
  network to connect to it, which the relay never does. `pcscf` answers such an
  offer with 488 Not Acceptable Here. RCS clients normally offer `active` or
  `actpass`; recorded as a limitation.
- `rcs-as` offers `a=setup:passive` on terminating sessions so the relay can
  connect to it.

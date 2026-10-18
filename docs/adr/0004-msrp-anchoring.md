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
  to `rcs-as`**, whenever the client allows it. RFC 6135 §4.2.2 forbids
  `a=setup:passive` in an offer, so the direction is reached through answers and
  `actpass` offers, never by offering `passive`:

  | Session | Offer the far side sees | Answer the offerer sees |
  |---|---|---|
  | Client originates (client offers `actpass` or `active`) | to `rcs-as`: relay core address, `actpass`; `rcs-as` answers `passive` | to client: relay public address, `passive` |
  | `rcs-as` originates (`rcs-as` offers `actpass`, its instance address) | to client: relay public address, `actpass` | to `rcs-as`: `active` (relay connects) |

  When the client answers a terminating `actpass` offer with `active`, which a
  client behind NAT does (§4.2.2), it connects to the relay. When it answers
  `passive`, the relay dials the client's `a=path` address as a fallback, which
  works only if the client is reachable; the failure is counted and the session
  falls back to store-and-forward in `rcs-as`.
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

Making the client the connecting side whenever it allows it removes the need for
connection affinity behind the NLB and works through NAT; the outbound fallback
exists only so a compliant client that answers `passive` is not refused. Using the gateway model matches how operators deploy
RCS and keeps the client unaware of the relay.

## Consequences

- `pcscf` must rewrite SDP correctly in offers and answers, initial and re-INVITE,
  and release bindings on BYE, CANCEL, failure responses and session timer expiry.
- A client that offers `a=setup:passive` violates RFC 6135 §4.2.2; `pcscf`
  answers such an offer with 488 Not Acceptable Here.
- A binding whose client leg is outbound (client answered `passive`) is served by
  the relay task that dials, so it is claimed at dial time like an inbound one.
- The relay needs egress to the internet for the fallback dial; security groups
  allow it only toward the ports clients put in `a=path`.

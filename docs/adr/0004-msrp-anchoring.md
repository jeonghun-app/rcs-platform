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
- RFC 4976 relay mode (AUTH) is an optional later feature for clients that ask for
  it.

## Rationale

Fixing the connection direction removes the need for connection affinity behind
the NLB and works through NAT. Using the gateway model matches how operators deploy
RCS and keeps the client unaware of the relay.

## Consequences

- `pcscf` must rewrite SDP correctly in offers and answers, initial and re-INVITE,
  and release bindings on BYE, CANCEL, failure responses and session timer expiry.
- A client that insists on `a=setup:passive` in its answer cannot be served; the
  relay answers with a 488 through `pcscf`. Recorded as a limitation.
- `rcs-as` offers `a=setup:passive` on terminating sessions so the relay can
  connect to it.

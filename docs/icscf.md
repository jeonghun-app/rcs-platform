# icscf

`icscf` is the Interrogating-CSCF: the home network's contact point for
REGISTER and for requests to its users (TS 24.229 §5.3). For each one it asks
the HSS which S-CSCF serves the user (Cx UAR or LIR, TS 29.228) and sends the
request there. It keeps nothing about users, so any task can take any
request. The service is `internal/icscf`, whose package documentation holds
the mapping of every HSS answer to a SIP response with its clause;
`cmd/icscf` only wires it to `internal/runtime`.

## What it does

- **REGISTER**: a UAR, then the REGISTER's Request-URI becomes the S-CSCF's.
  A REGISTER the S-CSCF does not answer within `ICSCF_REGISTER_TIMEOUT` is
  answered 504 (§5.3.1.3).
- **A request for a user** (no To tag, no Route left): an LIR, then the
  S-CSCF becomes the topmost Route. A `user=phone` SIP URI is looked up, and
  forwarded, as its tel URI.
- **A request with a Route left, or inside a dialog**: forwarded where it
  says, without the HSS. `icscf` inserts no Record-Route, so dialogs do not
  pass it.
- **When the HSS cannot be asked**, or answers that it could not do it
  (`DIAMETER_UNABLE_TO_COMPLY`, a store failure): 480 with `Retry-After`
  (`ICSCF_RETRY_AFTER`). When the S-CSCF cannot be reached: 500 with the same
  `Retry-After`, which the originating S-CSCF passes on (a 503 it would turn
  into a 500 without one).
- **An ACK without a To tag**: dropped.

The S-CSCF is the one the HSS names (as Server-Name, or first among the names
in its capabilities, TS 29.228 §6.7), or else the first in `ICSCF_SCSCF` that
has every mandatory capability the HSS asks for, the one with the most
optional ones first. With none, a REGISTER is answered 600 and a request for
a user 480, counted as `icscf.scscf.no_capable`: a provisioning problem to
alarm on.

## Listener

`icscf` has one SIP listener, `ICSCF_CORE_ADDR` (TCP), which `pcscf` and
`scscf` reach by security group ([ADR 0007](adr/0007-internal-transport.md)).
No client reaches `icscf`, so it has no client-facing or UDP listener.

## Settings

The shared `RCS_` settings are in `internal/runtime`; `RCS_IMS_DOMAIN` is
required.

| Variable | Default | Meaning |
|---|---|---|
| `ICSCF_NAMESPACE` | `RCS_SERVICE_NAMESPACE`, else `rcs.local` | Cloud Map namespace: `hss` and `scscf` are found in it |
| `ICSCF_CORE_ADDR` | `0.0.0.0:5060` | the SIP listener |
| `ICSCF_CORE_HOST` | the task's private IPv4 address | this task's address, in the Via of what it forwards |
| `ICSCF_SCSCF` | `[{"uri":"sip:scscf.<namespace>:5060;transport=tcp"}]` | S-CSCFs to choose from, JSON: `uri`, and optional `mandatory` and `optional` capability numbers |
| `ICSCF_RETRY_AFTER` | `10s` | `Retry-After` of the 480 and 503 above, whole seconds up to 1 h |
| `ICSCF_REGISTER_TIMEOUT` | `16s` | how long a REGISTER waits for the S-CSCF, at most 32 s (the client's Timer F) |
| `ICSCF_DIAMETER_HOST` | `icscf-<random>.<namespace>` drawn at start ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)) | this task's Diameter identity |
| `ICSCF_DIAMETER_REALM` | `RCS_IMS_DOMAIN` | this task's Diameter realm |
| `ICSCF_HSS_REALM` | `ICSCF_DIAMETER_REALM` | the HSS's realm, every Cx request's Destination-Realm |
| `ICSCF_HSS_DISCOVERY` | `cloudmap` | how the HSS tasks are found: `cloudmap` (DiscoverInstances, every task) or `dns` (`hss.<namespace>`, at most eight tasks; refused in staging and prod) |
| `ICSCF_HSS_HOST_PATTERN` | `hss-*.<namespace>` | the Origin-Host every HSS task must have; a peer that claims another gets no request |
| `ICSCF_CX_TIMEOUT` | `5s` | one Cx attempt; a failed or busy one is retried once on another HSS task |

## Metrics

Counters, by the names `internal/icscf`'s package documentation lists:

| Counter | Counts |
|---|---|
| `icscf.<kind>.forwarded` | requests forwarded; `kind` is `register`, `terminating`, or `routed` (a Route left, or inside a dialog) |
| `icscf.<kind>.<code>` | requests icscf answered itself with `code` (403, 404, 480, 600) |
| `icscf.<kind>.cancelled` | requests cancelled while the HSS was asked |
| `icscf.hss.unavailable` | HSS queries that could not be completed; alarm on a rise |
| `icscf.hss.bad_server_name` | HSS answers naming an S-CSCF that is not a SIP URI |
| `icscf.scscf.no_capable` | answers no configured S-CSCF can take: a provisioning problem; alarm on any |
| `icscf.scscf.unreachable` | terminating requests answered 500 because the S-CSCF could not be reached |
| `icscf.routed.dropped_ack` | ACKs without a To tag, dropped |

`cxclient.*` counts the Cx answers by result code and their latency.

## Health

`/readyz` answers 503, naming `hss`, until a Diameter connection to an HSS
task is up; requests that arrive meanwhile get the 480 above.

## AWS permissions

With `ICSCF_HSS_DISCOVERY=cloudmap` the task role needs
`servicediscovery:DiscoverInstances` on the namespace's `hss` service.

## Not in place yet

- S-CSCF names are resolved only when they are IP addresses; DNS resolution
  of `scscf.<namespace>` comes with the shared resolver of #198.
- The transaction caps of #37 are not configurable here until it lands.
- S-CSCF re-selection, and the other parts of TS 24.229 §5.3 listed in the
  package documentation.

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

A name always wins over capabilities. This platform has one S-CSCF service,
and `hss` puts the names in `HSS_SCSCF_NAMES` into every Server-Capabilities
it sends, so while that is set the profile's capabilities choose nothing: no
REGISTER gets 600, and no request 480, for want of a capability. Capabilities
choose the S-CSCF only with `HSS_SCSCF_NAMES` unset ([hss](hss.md)).

## Reaching the S-CSCF

The S-CSCF's URI from `ICSCF_SCSCF` is resolved by its Cloud Map name inside
the namespace (`proxy.DNSResolver`, #198): every private address of
`scscf.<namespace>`, in a random order. A request goes to the first; when it
cannot be sent to one (the task is gone, its connection refused), it goes to
the next, counted as `icscf.scscf.next_address`. Once none is left, or when
the name has no address, it is answered 500 with `Retry-After`. Opening a
connection waits at most 2 s, since the address of a stopped task drops the
connection attempt rather than refusing it, and an address that failed goes to
the back of the list for 30 s, so it costs that wait once, not on every
request. 2 s leaves room for one lost connection attempt, which Linux sends
again after 1 s, so a healthy address is not sent to the back. The 2 s are
counted with the UAR and `ICSCF_REGISTER_TIMEOUT` against the client's 32 s. A REGISTER
the S-CSCF does not answer in time is not sent to another address, since that
S-CSCF may have taken it: it gets 504.

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
| `ICSCF_RETRY_AFTER` | `10s` | `Retry-After` of the 480 and 500 above, whole seconds up to 1 h |
| `ICSCF_REGISTER_TIMEOUT` | `16s` | how long a REGISTER waits for the S-CSCF; with twice `ICSCF_CX_TIMEOUT` (the UAR and its retry) under 32 s, the client's Timer F |
| `ICSCF_DIAMETER_HOST` | `icscf-<random>.<namespace>` drawn at start ([ADR 0005](adr/0005-shared-state-and-instance-addressing.md)) | this task's Diameter identity; leave unset in ECS (refused in staging and prod): every task needs its own, fresh at each start |
| `ICSCF_DIAMETER_REALM` | `RCS_IMS_DOMAIN` | this task's Diameter realm |
| `ICSCF_HSS_REALM` | `ICSCF_DIAMETER_REALM` | the HSS's realm, every Cx request's Destination-Realm |
| `ICSCF_HSS_DISCOVERY` | `cloudmap` | how the HSS tasks are found: `cloudmap` (DiscoverInstances, every task) or `dns` (`hss.<namespace>`, at most eight tasks; refused in staging and prod) |
| `ICSCF_HSS_HOST_PATTERN` | `hss-*.<namespace>` | the Origin-Host every HSS task must have; a peer that claims another gets no request |
| `ICSCF_CX_TIMEOUT` | `5s` | one Cx attempt; a failed or busy one is retried once on another HSS task |
| `ICSCF_DRAIN_TIMEOUT` | `RCS_SHUTDOWN_TIMEOUT` less 5 s | how long a stop waits for the requests in progress to get their final responses |

## Metrics

Counters, by the names `internal/icscf`'s package documentation lists:

| Counter | Counts |
|---|---|
| `icscf.<kind>.forwarded` | requests forwarded; `kind` is `register`, `terminating`, or `routed` (a Route left, or inside a dialog) |
| `icscf.<kind>.<code>` | requests icscf answered itself with `code` (403, 404, 480, 600), and 500 for an S-CSCF it could not reach |
| `icscf.<kind>.cancelled` | requests cancelled while the HSS was asked |
| `icscf.hss.unavailable` | HSS queries that could not be completed; alarm on a rise |
| `icscf.hss.bad_server_name` | HSS answers naming an S-CSCF that is not a SIP URI |
| `icscf.scscf.unknown_name` | answers naming an S-CSCF no configured one matches: a configuration problem; alarm on any |
| `icscf.scscf.no_capable` | answers no configured S-CSCF can take: a provisioning problem; alarm on any |
| `icscf.scscf.unreachable` | requests answered 500 because the S-CSCF could not be reached |
| `icscf.scscf.next_address` | requests sent to the next address of the S-CSCF after one refused |
| `icscf.routed.dropped_ack` | ACKs without a To tag, dropped |

`cxclient.*` counts the Cx answers by result code and their latency.

## Health

`/readyz` answers 503, naming `hss`, until a Diameter connection to an HSS
task is up, and again while none is; requests that arrive meanwhile get the
480 above. An HSS task that stops with a DPR is reconnected within a second
of its return; one whose connection broke without a DPR is held in the
watchdog's REOPEN state (RFC 3539 §3.4.1) for about a minute first.

## Stop

On SIGTERM `icscf` keeps its listener open and waits, for at most
`ICSCF_DRAIN_TIMEOUT`, until no request is in progress, so a REGISTER at the
S-CSCF or a ringing INVITE still gets its final response. A call that has
had its 2xx no longer counts, so a stop right after one returns at once.
A request still in progress at the end is answered, and its INVITE branches
are cancelled, so its sender tries another task at once instead of waiting
for its own timers (`proxy.Drain`, #281): a REGISTER with 503 and
`Retry-After`, which pcscf retries on another icscf at once, anything else
with 500 and `Retry-After` (#310).

## AWS permissions

With `ICSCF_HSS_DISCOVERY=cloudmap` the task role needs
`servicediscovery:DiscoverInstances` with both the namespace and its `hss`
service as resources: the call names both. Infra adds it on #56.

## Not in place yet

- The transaction caps of #37 are not configurable here until it lands.
- S-CSCF re-selection, and the other parts of TS 24.229 §5.3 listed in the
  package documentation.
